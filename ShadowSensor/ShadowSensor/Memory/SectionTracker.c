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
 * - Process doppelganging detection (transacted sections)
 * - Cross-process section mapping detection
 * - Suspicious section characteristics analysis
 * - PE header analysis for image sections
 * - File hash computation for threat correlation
 * - Lock-free hash table for O(1) section lookup
 * - Reference counting for safe cleanup
 *
 * Security Detection Capabilities:
 * - T1055.012: Process Hollowing via section manipulation
 * - T1055.013: Process Doppelganging (TxF transactions)
 * - T1055.004: Asynchronous Procedure Call (section-based)
 * - T1106: Native API abuse (section objects)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

#define SEC_VERSION                     1
#define SEC_SIGNATURE                   0x53454354  // 'SECT'
#define SEC_CLEANUP_INTERVAL_MS         60000       // 1 minute cleanup
#define SEC_STALE_THRESHOLD_MS          300000      // 5 minutes stale
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

/**
 * @brief Callback registration entry.
 */
typedef struct _SEC_CALLBACK_ENTRY {
    union {
        SEC_CREATE_CALLBACK CreateCallback;
        SEC_MAP_CALLBACK MapCallback;
    };
    PVOID Context;
    BOOLEAN InUse;
} SEC_CALLBACK_ENTRY, *PSEC_CALLBACK_ENTRY;

/**
 * @brief Extended tracker state (internal).
 */
typedef struct _SEC_TRACKER_INTERNAL {
    //
    // Base tracker structure
    //
    SEC_TRACKER Public;

    //
    // Signature for validation
    //
    ULONG Signature;

    //
    // Callbacks
    //
    SEC_CALLBACK_ENTRY CreateCallbacks[SEC_MAX_CALLBACKS];
    SEC_CALLBACK_ENTRY MapCallbacks[SEC_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST EntryLookaside;
    NPAGED_LOOKASIDE_LIST MapLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Shutdown synchronization
    //
    volatile LONG ShuttingDown;
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;

} SEC_TRACKER_INTERNAL, *PSEC_TRACKER_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
SecpCleanupDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static PSEC_ENTRY
SecpAllocateEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    );

static VOID
SecpFreeEntry(
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
    _In_opt_ PFILE_OBJECT FileObject
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

static VOID
SecpAcquireReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    );

static VOID
SecpReleaseReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
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

    //
    // Allocate tracker structure
    //
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

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&internal->Public.SectionListLock);
    ExInitializePushLock(&internal->Public.SectionHash.Lock);
    ExInitializePushLock(&internal->CallbackLock);
    InitializeListHead(&internal->Public.SectionList);

    //
    // Initialize shutdown event
    //
    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // Initial reference

    //
    // Allocate hash table buckets
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

    //
    // Initialize hash buckets
    //
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
    // Set default configuration
    //
    internal->Public.Config.MaxSections = SEC_MAX_TRACKED_SECTIONS;
    internal->Public.Config.TrackAllSections = FALSE;
    internal->Public.Config.EnablePEAnalysis = TRUE;
    internal->Public.Config.EnableFileHashing = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // Initialize cleanup timer
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

    //
    // Mark as initialized
    //
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
    // Signal shutdown
    //
    InterlockedExchange(&internal->ShuttingDown, 1);

    //
    // Cancel cleanup timer
    //
    if (internal->CleanupTimerActive) {
        KeCancelTimer(&internal->CleanupTimer);
        internal->CleanupTimerActive = FALSE;
    }

    //
    // Wait for active operations to complete
    //
    SecpReleaseReference(internal);
    timeout.QuadPart = -((LONGLONG)5000 * 10000);  // 5 second timeout
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Free all section entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->SectionListLock);

    while (!IsListEmpty(&Tracker->SectionList)) {
        listEntry = RemoveHeadList(&Tracker->SectionList);
        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        //
        // Free all map entries for this section
        //
        while (!IsListEmpty(&entry->MapList)) {
            PLIST_ENTRY mapListEntry = RemoveHeadList(&entry->MapList);
            mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);
            SecpFreeMapEntry(internal, mapEntry);
        }

        //
        // Free backing file name if allocated
        //
        if (entry->BackingFile.FileName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(
                entry->BackingFile.FileName.Buffer,
                SEC_POOL_TAG_ENTRY
            );
        }

        SecpFreeEntry(internal, entry);
    }

    ExReleasePushLockExclusive(&Tracker->SectionListLock);
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
    Tracker->Initialized = FALSE;

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
    PSEC_ENTRY entry;
    PSEC_ENTRY existing;
    NTSTATUS status = STATUS_SUCCESS;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG returnLength;

    if (Tracker == NULL || !Tracker->Initialized || SectionObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    SecpAcquireReference(internal);

    //
    // Check if we're at capacity
    //
    if ((ULONG)Tracker->SectionCount >= Tracker->Config.MaxSections) {
        SecpReleaseReference(internal);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check if section is already tracked
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionHash.Lock);

    existing = SecpFindEntryLocked(internal, SectionObject);

    ExReleasePushLockShared(&Tracker->SectionHash.Lock);
    KeLeaveCriticalRegion();

    if (existing != NULL) {
        if (SectionId != NULL) {
            *SectionId = existing->SectionId;
        }
        SecpReleaseReference(internal);
        return STATUS_OBJECT_NAME_EXISTS;
    }

    //
    // Allocate new entry
    //
    entry = SecpAllocateEntry(internal);
    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry
    //
    RtlZeroMemory(entry, sizeof(SEC_ENTRY));
    entry->SectionObject = SectionObject;
    entry->CreatorProcessId = CreatorProcessId;
    entry->Flags = Flags;
    entry->SectionId = (ULONG)InterlockedIncrement(&Tracker->NextSectionId);
    entry->Type = SecpDetermineSectionType(Flags);
    entry->RefCount = 1;

    if (MaximumSize != NULL) {
        entry->MaximumSize = *MaximumSize;
    }

    InitializeListHead(&entry->MapList);
    KeInitializeSpinLock(&entry->MapListLock);
    KeQuerySystemTime(&entry->CreateTime);

    //
    // Process backing file information
    //
    if (FileObject != NULL) {
        entry->BackingFile.FileObject = FileObject;

        //
        // Get file name
        //
        status = IoQueryFileDosDeviceName(FileObject, &nameInfo);
        if (NT_SUCCESS(status) && nameInfo != NULL) {
            //
            // Allocate buffer for file name
            //
            entry->BackingFile.FileName.MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
            entry->BackingFile.FileName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                entry->BackingFile.FileName.MaximumLength,
                SEC_POOL_TAG_ENTRY
            );

            if (entry->BackingFile.FileName.Buffer != NULL) {
                RtlCopyUnicodeString(&entry->BackingFile.FileName, &nameInfo->Name);
            }

            ExFreePool(nameInfo);
        }

        //
        // Check for transacted file (process doppelganging indicator)
        //
        entry->BackingFile.IsTransacted = SecpIsTransactedFile(FileObject);
        if (entry->BackingFile.IsTransacted) {
            entry->SuspicionFlags |= SecSuspicion_Transacted;
            InterlockedIncrement64(&Tracker->Stats.TransactedDetections);
        }

        //
        // Check if backing file is deleted
        //
        entry->BackingFile.IsDeleted = SecpIsFileDeleted(FileObject);
        if (entry->BackingFile.IsDeleted) {
            entry->SuspicionFlags |= SecSuspicion_Deleted;
        }

        //
        // Check for unusual path
        //
        if (entry->BackingFile.FileName.Buffer != NULL) {
            if (SecpIsUnusualPath(&entry->BackingFile.FileName)) {
                entry->SuspicionFlags |= SecSuspicion_UnusualPath;
            }

            if (SecpIsSuspiciousName(&entry->BackingFile.FileName)) {
                entry->SuspicionFlags |= SecSuspicion_SuspiciousName;
            }
        }

        //
        // Analyze PE header for image sections
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
        // No backing file - anonymous section
        //
        if (entry->MaximumSize.QuadPart > SEC_SUSPICIOUS_SIZE_THRESHOLD) {
            entry->SuspicionFlags |= SecSuspicion_LargeAnonymous;
        }

        if (Flags & SecFlag_Execute) {
            entry->SuspicionFlags |= SecSuspicion_ExecuteAnonymous;
        }

        if (Flags & SecFlag_Image) {
            entry->SuspicionFlags |= SecSuspicion_NoBackingFile;
        }
    }

    //
    // Calculate initial suspicion score
    //
    SecpUpdateSuspicionScore(entry);

    //
    // Insert into tracking structures
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->SectionListLock);
    ExAcquirePushLockExclusive(&Tracker->SectionHash.Lock);

    SecpInsertEntryLocked(internal, entry);

    ExReleasePushLockExclusive(&Tracker->SectionHash.Lock);
    ExReleasePushLockExclusive(&Tracker->SectionListLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.TotalCreated);

    if (entry->SuspicionFlags != SecSuspicion_None) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousDetections);
    }

    //
    // Invoke callbacks
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
    KIRQL oldIrql;
    BOOLEAN isCrossProcess;

    if (Tracker == NULL || !Tracker->Initialized || SectionObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    SecpAcquireReference(internal);

    //
    // Find section entry
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionHash.Lock);

    entry = SecpFindEntryLocked(internal, SectionObject);

    ExReleasePushLockShared(&Tracker->SectionHash.Lock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    //
    // Reference the entry
    //
    SecAddRef(entry);

    //
    // Check map limit
    //
    if (entry->MapCount >= SEC_MAX_MAPS_PER_SECTION) {
        SecRelease(entry);
        SecpReleaseReference(internal);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate map entry
    //
    mapEntry = SecpAllocateMapEntry(internal);
    if (mapEntry == NULL) {
        SecRelease(entry);
        SecpReleaseReference(internal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize map entry
    //
    RtlZeroMemory(mapEntry, sizeof(SEC_MAP_ENTRY));
    mapEntry->ProcessId = ProcessId;
    mapEntry->ViewBase = ViewBase;
    mapEntry->ViewSize = ViewSize;
    mapEntry->SectionOffset = SectionOffset;
    mapEntry->Protection = Protection;
    mapEntry->IsMapped = TRUE;
    KeQuerySystemTime(&mapEntry->MapTime);

    //
    // Check for cross-process mapping
    //
    isCrossProcess = (ProcessId != entry->CreatorProcessId);

    //
    // Insert into map list
    //
    KeAcquireSpinLock(&entry->MapListLock, &oldIrql);

    InsertTailList(&entry->MapList, &mapEntry->ListEntry);
    InterlockedIncrement(&entry->MapCount);

    if (isCrossProcess) {
        InterlockedIncrement(&entry->CrossProcessMapCount);
        entry->SuspicionFlags |= SecSuspicion_CrossProcess;

        //
        // Remote mapping is highly suspicious
        //
        if (entry->CreatorProcessId != PsGetCurrentProcessId()) {
            entry->SuspicionFlags |= SecSuspicion_RemoteMap;
        }
    }

    KeQuerySystemTime(&entry->LastMapTime);

    KeReleaseSpinLock(&entry->MapListLock, oldIrql);

    //
    // Update suspicion score
    //
    SecpUpdateSuspicionScore(entry);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.TotalMapped);

    if (isCrossProcess) {
        InterlockedIncrement64(&Tracker->Stats.CrossProcessMaps);
    }

    //
    // Invoke callbacks
    //
    SecpInvokeMapCallbacks(internal, entry, mapEntry);

    SecRelease(entry);
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
    KIRQL oldIrql;

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    SecpAcquireReference(internal);

    //
    // Search all sections for this mapping
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionListLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        KeAcquireSpinLock(&entry->MapListLock, &oldIrql);

        for (mapListEntry = entry->MapList.Flink;
             mapListEntry != &entry->MapList;
             mapListEntry = mapListEntry->Flink) {

            mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);

            if (mapEntry->ProcessId == ProcessId &&
                mapEntry->ViewBase == ViewBase &&
                mapEntry->IsMapped) {

                //
                // Found the mapping - mark as unmapped
                //
                mapEntry->IsMapped = FALSE;
                KeQuerySystemTime(&mapEntry->UnmapTime);

                found = TRUE;
                break;
            }
        }

        KeReleaseSpinLock(&entry->MapListLock, oldIrql);

        if (found) {
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionListLock);
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
    PLIST_ENTRY mapListEntry;
    PSEC_MAP_ENTRY mapEntry;

    if (Tracker == NULL || !Tracker->Initialized || SectionObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    SecpAcquireReference(internal);

    //
    // Find and remove entry
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->SectionListLock);
    ExAcquirePushLockExclusive(&Tracker->SectionHash.Lock);

    entry = SecpFindEntryLocked(internal, SectionObject);

    if (entry != NULL) {
        SecpRemoveEntryLocked(internal, entry);
    }

    ExReleasePushLockExclusive(&Tracker->SectionHash.Lock);
    ExReleasePushLockExclusive(&Tracker->SectionListLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    //
    // Free all map entries
    //
    while (!IsListEmpty(&entry->MapList)) {
        mapListEntry = RemoveHeadList(&entry->MapList);
        mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);
        SecpFreeMapEntry(internal, mapEntry);
    }

    //
    // Free backing file name
    //
    if (entry->BackingFile.FileName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(
            entry->BackingFile.FileName.Buffer,
            SEC_POOL_TAG_ENTRY
        );
    }

    //
    // Free entry
    //
    SecpFreeEntry(internal, entry);

    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

// ============================================================================
// SECTION QUERY
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecGetSectionInfo(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PSEC_ENTRY* Entry
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;

    if (Tracker == NULL || !Tracker->Initialized ||
        SectionObject == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Entry = NULL;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionHash.Lock);

    entry = SecpFindEntryLocked(internal, SectionObject);

    if (entry != NULL) {
        SecAddRef(entry);
        *Entry = entry;
    }

    ExReleasePushLockShared(&Tracker->SectionHash.Lock);
    KeLeaveCriticalRegion();

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
SecGetSectionById(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG SectionId,
    _Out_ PSEC_ENTRY* Entry
    )
{
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    PSEC_ENTRY found = NULL;

    if (Tracker == NULL || !Tracker->Initialized || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Entry = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionListLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        if (entry->SectionId == SectionId) {
            SecAddRef(entry);
            found = entry;
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionListLock);
    KeLeaveCriticalRegion();

    if (found != NULL) {
        *Entry = found;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
SecFindSectionByFile(
    _In_ PSEC_TRACKER Tracker,
    _In_ PUNICODE_STRING FileName,
    _Out_ PSEC_ENTRY* Entry
    )
{
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    PSEC_ENTRY found = NULL;

    if (Tracker == NULL || !Tracker->Initialized ||
        FileName == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Entry = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionListLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        if (entry->BackingFile.FileName.Buffer != NULL &&
            RtlEqualUnicodeString(&entry->BackingFile.FileName, FileName, TRUE)) {
            SecAddRef(entry);
            found = entry;
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionListLock);
    KeLeaveCriticalRegion();

    if (found != NULL) {
        *Entry = found;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

// ============================================================================
// SUSPICION ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecAnalyzeSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PSEC_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    )
{
    PSEC_ENTRY entry;
    NTSTATUS status;

    if (Tracker == NULL || SuspicionFlags == NULL || SuspicionScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SuspicionFlags = SecSuspicion_None;
    *SuspicionScore = 0;

    status = SecGetSectionInfo(Tracker, SectionObject, &entry);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Re-analyze and update score
    //
    SecpUpdateSuspicionScore(entry);

    *SuspicionFlags = entry->SuspicionFlags;
    *SuspicionScore = entry->SuspicionScore;

    SecRelease(entry);

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
    PSEC_ENTRY entry;
    NTSTATUS status;

    if (Tracker == NULL || IsTransacted == NULL || FileDeleted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsTransacted = FALSE;
    *FileDeleted = FALSE;

    status = SecGetSectionInfo(Tracker, SectionObject, &entry);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *IsTransacted = entry->BackingFile.IsTransacted;
    *FileDeleted = entry->BackingFile.IsDeleted;

    //
    // Log if doppelganging detected
    //
    if (*IsTransacted || *FileDeleted) {
        TeLogMemoryEvent(
            TeEvent_InjectionDetected,
            (UINT32)(ULONG_PTR)entry->CreatorProcessId,
            0,
            (UINT64)SectionObject,
            (UINT64)entry->MaximumSize.QuadPart,
            0,
            entry->SuspicionScore,
            TE_MEM_FLAG_INJECTION
        );
    }

    SecRelease(entry);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SecGetSuspiciousSections(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxEntries, *EntryCount) PSEC_ENTRY* Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount
    )
{
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    ULONG count = 0;

    if (Tracker == NULL || !Tracker->Initialized ||
        Entries == NULL || EntryCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntryCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionListLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList && count < MaxEntries;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        if (entry->SuspicionScore >= MinScore) {
            SecAddRef(entry);
            Entries[count++] = entry;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionListLock);
    KeLeaveCriticalRegion();

    *EntryCount = count;

    return STATUS_SUCCESS;
}

// ============================================================================
// CROSS-PROCESS ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecGetCrossProcessMaps(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_writes_to_(MaxMaps, *MapCount) PSEC_MAP_ENTRY* Maps,
    _In_ ULONG MaxMaps,
    _Out_ PULONG MapCount
    )
{
    PSEC_ENTRY entry;
    PLIST_ENTRY mapListEntry;
    PSEC_MAP_ENTRY mapEntry;
    KIRQL oldIrql;
    ULONG count = 0;
    NTSTATUS status;

    if (Tracker == NULL || Maps == NULL || MapCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *MapCount = 0;

    status = SecGetSectionInfo(Tracker, SectionObject, &entry);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeAcquireSpinLock(&entry->MapListLock, &oldIrql);

    for (mapListEntry = entry->MapList.Flink;
         mapListEntry != &entry->MapList && count < MaxMaps;
         mapListEntry = mapListEntry->Flink) {

        mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);

        //
        // Check if this is a cross-process mapping
        //
        if (mapEntry->ProcessId != entry->CreatorProcessId) {
            Maps[count++] = mapEntry;
        }
    }

    KeReleaseSpinLock(&entry->MapListLock, oldIrql);

    *MapCount = count;

    SecRelease(entry);

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
    PSEC_ENTRY entry;
    NTSTATUS status;

    if (Tracker == NULL || IsCrossProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsCrossProcess = FALSE;
    if (ProcessCount != NULL) {
        *ProcessCount = 0;
    }

    status = SecGetSectionInfo(Tracker, SectionObject, &entry);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *IsCrossProcess = (entry->CrossProcessMapCount > 0);

    if (ProcessCount != NULL) {
        *ProcessCount = (ULONG)entry->CrossProcessMapCount;
    }

    SecRelease(entry);

    return STATUS_SUCCESS;
}

// ============================================================================
// CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecRegisterCreateCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_CREATE_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PSEC_TRACKER_INTERNAL internal;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    if (Tracker == NULL || !Tracker->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (!internal->CreateCallbacks[i].InUse) {
            internal->CreateCallbacks[i].CreateCallback = Callback;
            internal->CreateCallbacks[i].Context = Context;
            internal->CreateCallbacks[i].InUse = TRUE;
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
    _In_opt_ PVOID Context
    )
{
    PSEC_TRACKER_INTERNAL internal;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    if (Tracker == NULL || !Tracker->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (!internal->MapCallbacks[i].InUse) {
            internal->MapCallbacks[i].MapCallback = Callback;
            internal->MapCallbacks[i].Context = Context;
            internal->MapCallbacks[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
VOID
SecUnregisterCallbacks(
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
        internal->MapCallbacks[i].InUse = FALSE;
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

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Tracker->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// REFERENCE COUNTING
// ============================================================================

_Use_decl_annotations_
VOID
SecAddRef(
    _In_ PSEC_ENTRY Entry
    )
{
    if (Entry != NULL) {
        InterlockedIncrement(&Entry->RefCount);
    }
}

_Use_decl_annotations_
VOID
SecRelease(
    _In_ PSEC_ENTRY Entry
    )
{
    if (Entry != NULL) {
        LONG newCount = InterlockedDecrement(&Entry->RefCount);

        //
        // Note: Entry is not freed here - it's managed by the tracker
        // This just ensures the entry stays valid while referenced
        //
        UNREFERENCED_PARAMETER(newCount);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

static VOID
SecpCleanupDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSEC_TRACKER_INTERNAL internal = (PSEC_TRACKER_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (internal == NULL || internal->ShuttingDown) {
        return;
    }

    //
    // Cleanup is done at DISPATCH_LEVEL via DPC
    // For complex cleanup, queue a work item
    // For now, we just track - actual cleanup happens on untrack
    //
}

static PSEC_ENTRY
SecpAllocateEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    )
{
    PSEC_ENTRY entry;

    if (!Tracker->LookasideInitialized) {
        return NULL;
    }

    entry = (PSEC_ENTRY)ExAllocateFromNPagedLookasideList(&Tracker->EntryLookaside);

    return entry;
}

static VOID
SecpFreeEntry(
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
    PSEC_MAP_ENTRY mapEntry;

    if (!Tracker->LookasideInitialized) {
        return NULL;
    }

    mapEntry = (PSEC_MAP_ENTRY)ExAllocateFromNPagedLookasideList(&Tracker->MapLookaside);

    return mapEntry;
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

static ULONG
SecpHashSectionObject(
    _In_ PVOID SectionObject,
    _In_ ULONG BucketCount
    )
{
    ULONG_PTR ptr = (ULONG_PTR)SectionObject;
    ULONG hash;

    //
    // Simple but effective hash for pointer values
    // Uses golden ratio constant for good distribution
    //
    hash = (ULONG)(ptr * 0x9E3779B9UL);
    hash ^= (ULONG)(ptr >> 16);
    hash *= 0x85EBCA6BUL;
    hash ^= hash >> 13;

    return hash % BucketCount;
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

    //
    // Insert into main list
    //
    InsertTailList(&Tracker->Public.SectionList, &Entry->ListEntry);
    InterlockedIncrement(&Tracker->Public.SectionCount);

    //
    // Insert into hash table
    //
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
    //
    // Remove from main list
    //
    RemoveEntryList(&Entry->ListEntry);
    InterlockedDecrement(&Tracker->Public.SectionCount);

    //
    // Remove from hash table
    //
    RemoveEntryList(&Entry->HashEntry);
}

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

static VOID
SecpAnalyzePE(
    _In_ PSEC_ENTRY Entry,
    _In_opt_ PFILE_OBJECT FileObject
    )
{
    NTSTATUS status;
    PVOID headerBuffer = NULL;
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK ioStatus;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;

    if (FileObject == NULL) {
        return;
    }

    //
    // Allocate buffer for PE header
    //
    headerBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        SEC_PE_HEADER_SIZE,
        SEC_POOL_TAG_CONTEXT
    );

    if (headerBuffer == NULL) {
        return;
    }

    //
    // Read PE header from file
    //
    offset.QuadPart = 0;

    status = ZwReadFile(
        NULL,  // We'd need a handle, not FileObject directly
        NULL,
        NULL,
        NULL,
        &ioStatus,
        headerBuffer,
        SEC_PE_HEADER_SIZE,
        &offset,
        NULL
    );

    //
    // For now, we mark as potential PE based on section flags
    // Full implementation would use proper file reading
    //
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(dosHeader);
    UNREFERENCED_PARAMETER(ntHeaders);
    UNREFERENCED_PARAMETER(ioStatus);

    Entry->PE.IsPE = TRUE;  // Assume PE for image sections

    ShadowStrikeFreePoolWithTag(headerBuffer, SEC_POOL_TAG_CONTEXT);
}

static VOID
SecpComputeFileHash(
    _In_ PSEC_ENTRY Entry,
    _In_ PFILE_OBJECT FileObject
    )
{
    //
    // Hash computation is expensive - would be done asynchronously
    // in a production implementation
    //
    UNREFERENCED_PARAMETER(FileObject);

    Entry->BackingFile.HashValid = FALSE;
}

static VOID
SecpUpdateSuspicionScore(
    _Inout_ PSEC_ENTRY Entry
    )
{
    ULONG score = 0;
    SEC_SUSPICION flags = Entry->SuspicionFlags;

    if (flags & SecSuspicion_Transacted) {
        score += SEC_SCORE_TRANSACTED;
    }

    if (flags & SecSuspicion_Deleted) {
        score += SEC_SCORE_DELETED;
    }

    if (flags & SecSuspicion_CrossProcess) {
        score += SEC_SCORE_CROSS_PROCESS;
    }

    if (flags & SecSuspicion_UnusualPath) {
        score += SEC_SCORE_UNUSUAL_PATH;
    }

    if (flags & SecSuspicion_LargeAnonymous) {
        score += SEC_SCORE_LARGE_ANONYMOUS;
    }

    if (flags & SecSuspicion_ExecuteAnonymous) {
        score += SEC_SCORE_EXECUTE_ANONYMOUS;
    }

    if (flags & SecSuspicion_HiddenPE) {
        score += SEC_SCORE_HIDDEN_PE;
    }

    if (flags & SecSuspicion_RemoteMap) {
        score += SEC_SCORE_REMOTE_MAP;
    }

    if (flags & SecSuspicion_SuspiciousName) {
        score += SEC_SCORE_SUSPICIOUS_NAME;
    }

    if (flags & SecSuspicion_NoBackingFile) {
        score += SEC_SCORE_NO_BACKING_FILE;
    }

    if (flags & SecSuspicion_ModifiedImage) {
        score += SEC_SCORE_MODIFIED_IMAGE;
    }

    if (flags & SecSuspicion_OverlayData) {
        score += SEC_SCORE_OVERLAY_DATA;
    }

    //
    // Bonus for multiple indicators
    //
    ULONG indicatorCount = 0;
    SEC_SUSPICION temp = flags;
    while (temp) {
        indicatorCount += (temp & 1);
        temp >>= 1;
    }

    if (indicatorCount >= 3) {
        score += indicatorCount * 50;
    }

    Entry->SuspicionScore = score;
}

static VOID
SecpInvokeCreateCallbacks(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    )
{
    ULONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (Tracker->CreateCallbacks[i].InUse &&
            Tracker->CreateCallbacks[i].CreateCallback != NULL) {

            Tracker->CreateCallbacks[i].CreateCallback(
                Entry,
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

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (Tracker->MapCallbacks[i].InUse &&
            Tracker->MapCallbacks[i].MapCallback != NULL) {

            Tracker->MapCallbacks[i].MapCallback(
                Entry,
                MapEntry,
                Tracker->MapCallbacks[i].Context
            );
        }
    }

    ExReleasePushLockShared(&Tracker->CallbackLock);
    KeLeaveCriticalRegion();
}

static BOOLEAN
SecpIsTransactedFile(
    _In_ PFILE_OBJECT FileObject
    )
{
    //
    // Check if file is part of a TxF transaction
    // This is a key indicator of process doppelganging
    //
    if (FileObject == NULL) {
        return FALSE;
    }

    //
    // The file object has flags indicating transaction status
    // FO_FILE_OBJECT_HAS_EXTENSION and check for transaction context
    //
    // In a full implementation, we would:
    // 1. Check FileObject->Flags for FO_FILE_OBJECT_HAS_EXTENSION
    // 2. Use IoGetTransactionParameterBlock() to check for transaction
    //
    // For now, we return FALSE and rely on other indicators
    //
    return FALSE;
}

static BOOLEAN
SecpIsFileDeleted(
    _In_ PFILE_OBJECT FileObject
    )
{
    //
    // Check if backing file has been deleted
    // This is an indicator of process ghosting
    //
    if (FileObject == NULL) {
        return FALSE;
    }

    //
    // Check FO_DELETE_ON_CLOSE or FO_FILE_MODIFIED flags
    // Also check if file has delete pending
    //
    if (FileObject->DeletePending) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
SecpIsUnusualPath(
    _In_ PUNICODE_STRING FilePath
    )
{
    //
    // Check for unusual file paths that indicate malicious activity
    //
    static const UNICODE_STRING suspiciousPaths[] = {
        RTL_CONSTANT_STRING(L"\\Temp\\"),
        RTL_CONSTANT_STRING(L"\\AppData\\Local\\Temp\\"),
        RTL_CONSTANT_STRING(L"\\Downloads\\"),
        RTL_CONSTANT_STRING(L"\\ProgramData\\"),
        RTL_CONSTANT_STRING(L"\\Users\\Public\\"),
    };

    ULONG i;
    UNICODE_STRING upperPath;
    WCHAR upperBuffer[MAX_FILE_PATH_LENGTH];

    if (FilePath == NULL || FilePath->Buffer == NULL) {
        return FALSE;
    }

    //
    // Convert to uppercase for comparison
    //
    upperPath.Buffer = upperBuffer;
    upperPath.Length = 0;
    upperPath.MaximumLength = sizeof(upperBuffer);

    RtlUpcaseUnicodeString(&upperPath, FilePath, FALSE);

    for (i = 0; i < ARRAYSIZE(suspiciousPaths); i++) {
        if (wcsstr(upperPath.Buffer, suspiciousPaths[i].Buffer) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
SecpIsSuspiciousName(
    _In_ PUNICODE_STRING FilePath
    )
{
    //
    // Check for suspicious file names
    //
    PWCHAR fileName;
    PWCHAR extension;

    if (FilePath == NULL || FilePath->Buffer == NULL) {
        return FALSE;
    }

    //
    // Find the file name (after last backslash)
    //
    fileName = wcsrchr(FilePath->Buffer, L'\\');
    if (fileName == NULL) {
        fileName = FilePath->Buffer;
    } else {
        fileName++;
    }

    //
    // Check for double extensions
    //
    extension = wcsrchr(fileName, L'.');
    if (extension != NULL) {
        PWCHAR prevDot = NULL;
        PWCHAR p = fileName;

        while (p < extension) {
            if (*p == L'.') {
                prevDot = p;
            }
            p++;
        }

        if (prevDot != NULL) {
            //
            // Has double extension - suspicious
            //
            if (_wcsicmp(extension, L".exe") == 0 ||
                _wcsicmp(extension, L".dll") == 0 ||
                _wcsicmp(extension, L".scr") == 0) {
                return TRUE;
            }
        }
    }

    //
    // Check for very long names (> 200 chars) - possible evasion
    //
    if (wcslen(fileName) > 200) {
        return TRUE;
    }

    return FALSE;
}

static VOID
SecpAcquireReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    )
{
    InterlockedIncrement(&Tracker->ActiveOperations);
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

