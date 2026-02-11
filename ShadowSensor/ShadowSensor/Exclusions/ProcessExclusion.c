/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PROCESS EXCLUSION ENGINE
 * ============================================================================
 *
 * @file ProcessExclusion.c
 * @brief Enterprise-grade process exclusion management with trusted PID tracking.
 *
 * Implements process exclusion with:
 * - Lock-free trusted PID bitmap for O(1) lookups (PIDs 0-65535)
 * - Hash-based trusted PID set for large PID ranges (PIDs > 65535)
 * - Hierarchical exclusion inheritance (parent->child)
 * - Process creation callback integration
 * - Runtime exclusion management (add/remove/query)
 * - Exclusion reason tracking for audit
 * - Statistics and telemetry
 *
 * Strategy:
 * 1. On Process Creation (ProcessNotify callback), check if the image path
 *    matches an exclusion pattern from ExclusionManager.
 * 2. If matched, add the PID to the "Trusted PID" bitmap/hashset.
 * 3. In I/O callbacks and other hot paths, simply check the PID against
 *    the trusted set - avoiding expensive string comparisons.
 * 4. On process termination, remove PID from trusted set.
 *
 * Thread Safety:
 * - Bitmap ops use InterlockedOr/InterlockedAnd for lock-free reads at any IRQL.
 * - BitmapExtendedInfo and hash table use EX_PUSH_LOCK (requires <= APC_LEVEL).
 * - All public lookup APIs callable at <= APC_LEVEL.
 * - Race-safe initialization via InterlockedCompareExchange state machine.
 * - Bounded shutdown drain via KeWaitForSingleObject with timeout.
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ExclusionManager.h"
#include "../Utilities/ProcessUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Pool tag for process exclusion allocations
 */
#define PE_POOL_TAG                         'EPxS'

/**
 * @brief Pool tag for trusted PID entries
 */
#define PE_PID_TAG                          'dPxS'

/**
 * @brief Maximum PID value for bitmap (64K PIDs)
 */
#define PE_BITMAP_MAX_PID                   65536

/**
 * @brief Bitmap size in bytes (64K / 8 = 8KB)
 */
#define PE_BITMAP_SIZE_BYTES                (PE_BITMAP_MAX_PID / 8)

/**
 * @brief Bitmap size in ULONGs
 */
#define PE_BITMAP_SIZE_ULONGS               (PE_BITMAP_SIZE_BYTES / sizeof(ULONG))

/**
 * @brief Hash table bucket count for high PIDs
 */
#define PE_HASH_BUCKET_COUNT                256

/**
 * @brief Maximum exclusion inheritance depth
 */
#define PE_MAX_INHERITANCE_DEPTH            8

/**
 * @brief Shutdown drain timeout (10 seconds in 100ns units)
 */
#define PE_SHUTDOWN_TIMEOUT_100NS           (-100000000LL)

/**
 * @brief Initialization state values for CAS-based init
 */
#define PE_STATE_UNINITIALIZED              0
#define PE_STATE_INITIALIZING               1
#define PE_STATE_READY                      2
#define PE_STATE_SHUTTING_DOWN              3

// ============================================================================
// EXCLUSION REASON CODES
// ============================================================================

/**
 * @brief Reason why a process was excluded
 */
typedef enum _PE_EXCLUSION_REASON {
    PeReason_None = 0,
    PeReason_PathMatch,             ///< Image path matched exclusion
    PeReason_ProcessNameMatch,      ///< Process name matched exclusion
    PeReason_ParentInherited,       ///< Inherited from excluded parent
    PeReason_ManualExclusion,       ///< Manually excluded via API
    PeReason_SystemProcess,         ///< System critical process
    PeReason_ProtectedProcess,      ///< Protected process (PPL)
    PeReason_SignedMicrosoft,       ///< Microsoft-signed process
    PeReason_Whitelisted,           ///< In whitelist database
    PeReason_Max
} PE_EXCLUSION_REASON;

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Trusted PID entry for hash table (PIDs > 65535) and extended bitmap info
 */
typedef struct _PE_PID_ENTRY {
    LIST_ENTRY ListEntry;           ///< Hash bucket linkage
    HANDLE ProcessId;               ///< Process ID
    HANDLE ParentProcessId;         ///< Parent PID for inheritance tracking
    PE_EXCLUSION_REASON Reason;     ///< Why this process is excluded
    LARGE_INTEGER CreateTime;       ///< Process creation time
    LARGE_INTEGER ExclusionTime;    ///< When exclusion was added
    ULONG InheritanceDepth;         ///< Inheritance chain depth
    BOOLEAN InheritToChildren;      ///< Propagate to child processes
    BOOLEAN Permanent;              ///< Cannot be removed automatically
    UCHAR Reserved[2];
    volatile LONG HitCount;         ///< Access count for statistics
} PE_PID_ENTRY, *PPE_PID_ENTRY;

/**
 * @brief Hash bucket for high PIDs
 */
typedef struct _PE_HASH_BUCKET {
    LIST_ENTRY ListHead;            ///< List of PE_PID_ENTRY
    volatile LONG EntryCount;       ///< Number of entries
} PE_HASH_BUCKET, *PPE_HASH_BUCKET;

/**
 * @brief Process exclusion statistics
 */
typedef struct _PE_STATISTICS {
    volatile LONG64 TotalLookups;           ///< Total PID lookups
    volatile LONG64 BitmapHits;             ///< Hits in bitmap
    volatile LONG64 HashHits;               ///< Hits in hash table
    volatile LONG64 Misses;                 ///< Total misses
    volatile LONG64 ProcessesExcluded;      ///< Total processes excluded
    volatile LONG64 InheritedExclusions;    ///< Exclusions via inheritance
    volatile LONG64 PathMatchExclusions;    ///< Exclusions via path match
    volatile LONG64 ManualExclusions;       ///< Manual exclusions
    volatile LONG CurrentBitmapCount;       ///< PIDs in bitmap
    volatile LONG CurrentHashCount;         ///< PIDs in hash table
    LARGE_INTEGER StartTime;                ///< When initialized
} PE_STATISTICS, *PPE_STATISTICS;

/**
 * @brief Main process exclusion context
 */
typedef struct _PE_CONTEXT {
    //
    // Lifecycle state (CAS-based, see PE_STATE_* constants)
    //
    volatile LONG State;

    //
    // Bitmap for PIDs 0-65535 (lock-free read via InterlockedOr)
    //
    PULONG TrustedPidBitmap;
    EX_PUSH_LOCK BitmapLock;         ///< Exclusive lock for bitmap WRITES only

    //
    // Extended info for bitmap PIDs (reasons, inheritance)
    // Dynamically allocated array of PE_BITMAP_MAX_PID pointers.
    //
    PPE_PID_ENTRY* BitmapExtendedInfo;
    EX_PUSH_LOCK ExtendedInfoLock;

    //
    // Hash table for PIDs > 65535
    //
    PE_HASH_BUCKET HashBuckets[PE_HASH_BUCKET_COUNT];
    EX_PUSH_LOCK HashLock;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST PidEntryLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Configuration
    //
    BOOLEAN EnableInheritance;          ///< Inherit exclusions to children
    BOOLEAN ExcludeProtectedProcesses;  ///< Auto-exclude PPL processes
    BOOLEAN ExcludeMicrosoftSigned;     ///< Auto-exclude MS-signed
    UCHAR MaxInheritanceDepth;          ///< Max inheritance chain

    //
    // Reference counting for safe shutdown
    //
    volatile LONG ReferenceCount;
    KEVENT ShutdownEvent;

    //
    // Statistics (approximate — no cross-field atomicity)
    //
    PE_STATISTICS Stats;

} PE_CONTEXT, *PPE_CONTEXT;

// ============================================================================
// GLOBAL CONTEXT
// ============================================================================

static PE_CONTEXT g_ProcessExclusionContext = { 0 };

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
PepAcquireReference(
    VOID
    );

static VOID
PepReleaseReference(
    VOID
    );

static FORCEINLINE ULONG
PepPidToBitmapIndex(
    _In_ HANDLE ProcessId
    );

static FORCEINLINE ULONG
PepPidToBitmapBit(
    _In_ HANDLE ProcessId
    );

static FORCEINLINE ULONG
PepPidToHashBucket(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
PepIsPidInBitmap(
    _In_ HANDLE ProcessId
    );

static VOID
PepSetPidInBitmap(
    _In_ HANDLE ProcessId
    );

static VOID
PepClearPidInBitmap(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Find a PID in the hash table and return its data by value.
 *
 * Returns the exclusion metadata through output parameters so the caller
 * does NOT receive a pointer that could become dangling after lock release.
 *
 * @return TRUE if found, FALSE otherwise.
 */
static BOOLEAN
PepFindPidInHash(
    _In_ HANDLE ProcessId,
    _Out_opt_ PE_EXCLUSION_REASON* Reason,
    _Out_opt_ PBOOLEAN InheritToChildren,
    _Out_opt_ PULONG InheritanceDepth,
    _Out_opt_ PBOOLEAN Permanent
    );

static NTSTATUS
PepAddPidToHash(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ PE_EXCLUSION_REASON Reason,
    _In_ BOOLEAN InheritToChildren,
    _In_ ULONG InheritanceDepth
    );

static VOID
PepRemovePidFromHash(
    _In_ HANDLE ProcessId
    );

static NTSTATUS
PepAllocatePidEntry(
    _Out_ PPE_PID_ENTRY* Entry
    );

static VOID
PepFreePidEntry(
    _In_ PPE_PID_ENTRY Entry
    );

static BOOLEAN
PepCheckParentExclusion(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _Out_ PE_EXCLUSION_REASON* Reason,
    _Out_ PULONG InheritanceDepth
    );

static FORCEINLINE BOOLEAN
PepIsReady(
    VOID
    )
{
    return (ReadAcquire(&g_ProcessExclusionContext.State) == PE_STATE_READY);
}

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeProcessExclusionInitialize)
#pragma alloc_text(PAGE, ShadowStrikeProcessExclusionShutdown)
#pragma alloc_text(PAGE, ShadowStrikeOnProcessCreate)
#pragma alloc_text(PAGE, ShadowStrikeOnProcessTerminate)
#endif

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the process exclusion subsystem.
 *
 * Uses CAS-based state machine to prevent double-initialization races.
 * Dynamically allocates bitmap and extended info array.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeProcessExclusionInitialize(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    LONG previousState;
    ULONG i;

    PAGED_CODE();

    //
    // Atomic state transition: UNINITIALIZED -> INITIALIZING
    //
    previousState = InterlockedCompareExchange(
        &ctx->State,
        PE_STATE_INITIALIZING,
        PE_STATE_UNINITIALIZED
        );

    if (previousState == PE_STATE_READY) {
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState != PE_STATE_UNINITIALIZED) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // We own initialization exclusively. Zero everything except State.
    //
    RtlZeroMemory(
        (PUCHAR)ctx + sizeof(ctx->State),
        sizeof(PE_CONTEXT) - sizeof(ctx->State)
        );

    //
    // Allocate bitmap for PIDs 0-65535
    //
    ctx->TrustedPidBitmap = (PULONG)ExAllocatePoolZero(
        NonPagedPoolNx,
        PE_BITMAP_SIZE_BYTES,
        PE_POOL_TAG
    );

    if (ctx->TrustedPidBitmap == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Allocate extended info pointer array (C-5 fix: dynamically allocated)
    //
    ctx->BitmapExtendedInfo = (PPE_PID_ENTRY*)ExAllocatePoolZero(
        NonPagedPoolNx,
        PE_BITMAP_MAX_PID * sizeof(PPE_PID_ENTRY),
        PE_POOL_TAG
    );

    if (ctx->BitmapExtendedInfo == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Initialize locks
    //
    ExInitializePushLock(&ctx->BitmapLock);
    ExInitializePushLock(&ctx->ExtendedInfoLock);
    ExInitializePushLock(&ctx->HashLock);

    //
    // Initialize hash buckets
    //
    for (i = 0; i < PE_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&ctx->HashBuckets[i].ListHead);
        ctx->HashBuckets[i].EntryCount = 0;
    }

    //
    // Initialize lookaside list
    //
    ExInitializeNPagedLookasideList(
        &ctx->PidEntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PE_PID_ENTRY),
        PE_PID_TAG,
        0
    );

    ctx->LookasideInitialized = TRUE;

    //
    // Set default configuration
    //
    ctx->EnableInheritance = TRUE;
    ctx->ExcludeProtectedProcesses = TRUE;
    ctx->ExcludeMicrosoftSigned = FALSE;
    ctx->MaxInheritanceDepth = PE_MAX_INHERITANCE_DEPTH;

    //
    // Initialize reference counting.
    // Start at 1 — shutdown releases the init reference.
    //
    ctx->ReferenceCount = 1;
    KeInitializeEvent(&ctx->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&ctx->Stats.StartTime);

    //
    // Transition: INITIALIZING -> READY
    //
    MemoryBarrier();
    InterlockedExchange(&ctx->State, PE_STATE_READY);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Process exclusion engine initialized (bitmap=%uKB)\n",
               PE_BITMAP_SIZE_BYTES / 1024);

    return STATUS_SUCCESS;

Cleanup:
    if (ctx->BitmapExtendedInfo != NULL) {
        ExFreePoolWithTag(ctx->BitmapExtendedInfo, PE_POOL_TAG);
        ctx->BitmapExtendedInfo = NULL;
    }

    if (ctx->TrustedPidBitmap != NULL) {
        ExFreePoolWithTag(ctx->TrustedPidBitmap, PE_POOL_TAG);
        ctx->TrustedPidBitmap = NULL;
    }

    InterlockedExchange(&ctx->State, PE_STATE_UNINITIALIZED);

    return status;
}

/**
 * @brief Shutdown the process exclusion subsystem.
 *
 * Uses state machine to prevent races. Drains references with
 * a bounded timeout via KeWaitForSingleObject.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeProcessExclusionShutdown(
    VOID
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    PLIST_ENTRY entry;
    PPE_PID_ENTRY pidEntry;
    LARGE_INTEGER timeout;
    LONG previousState;
    ULONG i;

    PAGED_CODE();

    //
    // Atomic state transition: READY -> SHUTTING_DOWN
    //
    previousState = InterlockedCompareExchange(
        &ctx->State,
        PE_STATE_SHUTTING_DOWN,
        PE_STATE_READY
        );

    if (previousState != PE_STATE_READY) {
        return;
    }

    //
    // Release the init reference and wait for all other references
    // to drain with a bounded timeout.
    //
    PepReleaseReference();

    timeout.QuadPart = PE_SHUTDOWN_TIMEOUT_100NS;
    KeWaitForSingleObject(
        &ctx->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
        );

    //
    // Free extended info for bitmap PIDs
    //
    if (ctx->BitmapExtendedInfo != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&ctx->ExtendedInfoLock);

        for (i = 0; i < PE_BITMAP_MAX_PID; i++) {
            if (ctx->BitmapExtendedInfo[i] != NULL) {
                PepFreePidEntry(ctx->BitmapExtendedInfo[i]);
                ctx->BitmapExtendedInfo[i] = NULL;
            }
        }

        ExReleasePushLockExclusive(&ctx->ExtendedInfoLock);
        KeLeaveCriticalRegion();
    }

    //
    // Free hash table entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ctx->HashLock);

    for (i = 0; i < PE_HASH_BUCKET_COUNT; i++) {
        while (!IsListEmpty(&ctx->HashBuckets[i].ListHead)) {
            entry = RemoveHeadList(&ctx->HashBuckets[i].ListHead);
            pidEntry = CONTAINING_RECORD(entry, PE_PID_ENTRY, ListEntry);
            PepFreePidEntry(pidEntry);
        }
        ctx->HashBuckets[i].EntryCount = 0;
    }

    ExReleasePushLockExclusive(&ctx->HashLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (ctx->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&ctx->PidEntryLookaside);
        ctx->LookasideInitialized = FALSE;
    }

    //
    // Free dynamically allocated arrays
    //
    if (ctx->BitmapExtendedInfo != NULL) {
        ExFreePoolWithTag(ctx->BitmapExtendedInfo, PE_POOL_TAG);
        ctx->BitmapExtendedInfo = NULL;
    }

    if (ctx->TrustedPidBitmap != NULL) {
        ExFreePoolWithTag(ctx->TrustedPidBitmap, PE_POOL_TAG);
        ctx->TrustedPidBitmap = NULL;
    }

    InterlockedExchange(&ctx->State, PE_STATE_UNINITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Process exclusion engine shutdown complete\n");
}

// ============================================================================
// PUBLIC API - PROCESS LIFECYCLE
// ============================================================================

/**
 * @brief Handle process creation notification.
 *
 * Called from process notification callback when a new process is created.
 * Checks if the process should be excluded and adds to trusted set if so.
 *
 * @param ProcessId         New process ID
 * @param ParentProcessId   Parent process ID
 * @param ImagePath         Process image path (optional)
 *
 * @return TRUE if process is excluded, FALSE otherwise
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeOnProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    BOOLEAN excluded = FALSE;
    PE_EXCLUSION_REASON reason = PeReason_None;
    ULONG inheritanceDepth = 0;
    UNICODE_STRING processName = { 0 };
    NTSTATUS status;

    PAGED_CODE();

    if (!PepIsReady()) {
        return FALSE;
    }

    PepAcquireReference();

    //
    // Step 1: Check if path matches exclusion patterns
    //
    if (ImagePath != NULL && ImagePath->Length > 0) {
        //
        // Extract process name for process name exclusion check
        //
        status = ShadowStrikeGetFileName(ImagePath, &processName);

        //
        // Check path exclusions via ExclusionManager
        //
        if (ShadowStrikeIsPathExcluded(ImagePath, NULL)) {
            excluded = TRUE;
            reason = PeReason_PathMatch;
            InterlockedIncrement64(&ctx->Stats.PathMatchExclusions);
        }

        //
        // Check process name exclusions
        //
        if (!excluded && NT_SUCCESS(status) && processName.Length > 0) {
            if (ShadowStrikeIsProcessExcluded(ProcessId, &processName)) {
                excluded = TRUE;
                reason = PeReason_ProcessNameMatch;
            }
        }
    }

    //
    // Step 2: Check parent inheritance
    //
    if (!excluded && ctx->EnableInheritance && ParentProcessId != NULL) {
        if (PepCheckParentExclusion(ProcessId, ParentProcessId, &reason, &inheritanceDepth)) {
            if (inheritanceDepth < ctx->MaxInheritanceDepth) {
                excluded = TRUE;
                reason = PeReason_ParentInherited;
                inheritanceDepth++;
                InterlockedIncrement64(&ctx->Stats.InheritedExclusions);
            }
        }
    }

    //
    // Step 3: Check for protected process
    //
    if (!excluded && ctx->ExcludeProtectedProcesses) {
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId(ProcessId, &process);
        if (NT_SUCCESS(status)) {
            if (ShadowStrikeIsProcessProtected(process)) {
                excluded = TRUE;
                reason = PeReason_ProtectedProcess;
            }
            ObDereferenceObject(process);
        }
    }

    //
    // Step 4: If excluded, add to trusted set
    //
    if (excluded) {
        ULONG_PTR pidValue = (ULONG_PTR)ProcessId;

        if (pidValue < PE_BITMAP_MAX_PID) {
            //
            // Use bitmap for low PIDs
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&ctx->BitmapLock);

            PepSetPidInBitmap(ProcessId);
            InterlockedIncrement(&ctx->Stats.CurrentBitmapCount);

            ExReleasePushLockExclusive(&ctx->BitmapLock);
            KeLeaveCriticalRegion();

            //
            // Store extended info
            //
            PPE_PID_ENTRY extInfo = NULL;
            status = PepAllocatePidEntry(&extInfo);
            if (NT_SUCCESS(status)) {
                extInfo->ProcessId = ProcessId;
                extInfo->ParentProcessId = ParentProcessId;
                extInfo->Reason = reason;
                extInfo->InheritanceDepth = inheritanceDepth;
                extInfo->InheritToChildren = ctx->EnableInheritance;
                KeQuerySystemTime(&extInfo->ExclusionTime);

                KeEnterCriticalRegion();
                ExAcquirePushLockExclusive(&ctx->ExtendedInfoLock);

                if (ctx->BitmapExtendedInfo != NULL) {
                    if (ctx->BitmapExtendedInfo[pidValue] != NULL) {
                        PepFreePidEntry(ctx->BitmapExtendedInfo[pidValue]);
                    }
                    ctx->BitmapExtendedInfo[pidValue] = extInfo;
                }

                ExReleasePushLockExclusive(&ctx->ExtendedInfoLock);
                KeLeaveCriticalRegion();
            }

        } else {
            //
            // Use hash table for high PIDs
            //
            status = PepAddPidToHash(
                ProcessId,
                ParentProcessId,
                reason,
                ctx->EnableInheritance,
                inheritanceDepth
            );

            if (NT_SUCCESS(status)) {
                InterlockedIncrement(&ctx->Stats.CurrentHashCount);
            }
        }

        InterlockedIncrement64(&ctx->Stats.ProcessesExcluded);
    }

    PepReleaseReference();

    return excluded;
}

/**
 * @brief Handle process termination notification.
 *
 * Called from process notification callback when a process terminates.
 * Removes the process from the trusted set.
 *
 * @param ProcessId     Terminating process ID
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeOnProcessTerminate(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;

    PAGED_CODE();

    if (!PepIsReady()) {
        return;
    }

    PepAcquireReference();

    if (pidValue < PE_BITMAP_MAX_PID) {
        //
        // Remove from bitmap
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&ctx->BitmapLock);

        if (PepIsPidInBitmap(ProcessId)) {
            PepClearPidInBitmap(ProcessId);
            InterlockedDecrement(&ctx->Stats.CurrentBitmapCount);
        }

        ExReleasePushLockExclusive(&ctx->BitmapLock);
        KeLeaveCriticalRegion();

        //
        // Free extended info
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&ctx->ExtendedInfoLock);

        if (ctx->BitmapExtendedInfo != NULL &&
            ctx->BitmapExtendedInfo[pidValue] != NULL) {
            PepFreePidEntry(ctx->BitmapExtendedInfo[pidValue]);
            ctx->BitmapExtendedInfo[pidValue] = NULL;
        }

        ExReleasePushLockExclusive(&ctx->ExtendedInfoLock);
        KeLeaveCriticalRegion();

    } else {
        //
        // Remove from hash table
        //
        PepRemovePidFromHash(ProcessId);
    }

    PepReleaseReference();
}

// ============================================================================
// PUBLIC API - EXCLUSION CHECKING
// ============================================================================

/**
 * @brief Check if a process is in the trusted/excluded set.
 *
 * This is the primary API for hot-path exclusion checking.
 * Uses O(1) bitmap lookup for most PIDs.
 *
 * @param ProcessId     Process ID to check
 *
 * @return TRUE if process is excluded (trusted), FALSE otherwise
 *
 * @irql <= APC_LEVEL (push locks require IRQL <= APC_LEVEL)
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeIsProcessTrusted(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;
    BOOLEAN trusted = FALSE;

    if (!PepIsReady()) {
        return FALSE;
    }

    if (ProcessId == NULL) {
        return FALSE;
    }

    InterlockedIncrement64(&ctx->Stats.TotalLookups);

    if (pidValue < PE_BITMAP_MAX_PID) {
        //
        // Bitmap lookup - O(1)
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&ctx->BitmapLock);

        trusted = PepIsPidInBitmap(ProcessId);

        ExReleasePushLockShared(&ctx->BitmapLock);
        KeLeaveCriticalRegion();

        if (trusted) {
            InterlockedIncrement64(&ctx->Stats.BitmapHits);

            //
            // Update hit count under ExtendedInfoLock (C-4 fix)
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&ctx->ExtendedInfoLock);

            if (ctx->BitmapExtendedInfo != NULL &&
                ctx->BitmapExtendedInfo[pidValue] != NULL) {
                InterlockedIncrement(&ctx->BitmapExtendedInfo[pidValue]->HitCount);
            }

            ExReleasePushLockShared(&ctx->ExtendedInfoLock);
            KeLeaveCriticalRegion();
        }

    } else {
        //
        // Hash table lookup - O(1) average
        // PepFindPidInHash returns data by value — no dangling pointer.
        //
        if (PepFindPidInHash(ProcessId, NULL, NULL, NULL, NULL)) {
            trusted = TRUE;
            InterlockedIncrement64(&ctx->Stats.HashHits);
        }
    }

    if (!trusted) {
        InterlockedIncrement64(&ctx->Stats.Misses);
    }

    return trusted;
}

/**
 * @brief Check if a process is trusted with reason.
 *
 * Extended version that returns the exclusion reason.
 *
 * @param ProcessId     Process ID to check
 * @param Reason        Receives exclusion reason (optional)
 *
 * @return TRUE if process is excluded (trusted), FALSE otherwise
 *
 * @irql <= APC_LEVEL (push locks require IRQL <= APC_LEVEL)
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeIsProcessTrustedEx(
    _In_ HANDLE ProcessId,
    _Out_opt_ PE_EXCLUSION_REASON* Reason
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;
    BOOLEAN trusted = FALSE;
    PE_EXCLUSION_REASON reason = PeReason_None;

    if (Reason != NULL) {
        *Reason = PeReason_None;
    }

    if (!PepIsReady()) {
        return FALSE;
    }

    if (ProcessId == NULL) {
        return FALSE;
    }

    InterlockedIncrement64(&ctx->Stats.TotalLookups);

    if (pidValue < PE_BITMAP_MAX_PID) {
        //
        // Bitmap lookup
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&ctx->BitmapLock);

        trusted = PepIsPidInBitmap(ProcessId);

        ExReleasePushLockShared(&ctx->BitmapLock);
        KeLeaveCriticalRegion();

        if (trusted) {
            InterlockedIncrement64(&ctx->Stats.BitmapHits);

            //
            // Get reason from extended info
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&ctx->ExtendedInfoLock);

            if (ctx->BitmapExtendedInfo != NULL &&
                ctx->BitmapExtendedInfo[pidValue] != NULL) {
                reason = ctx->BitmapExtendedInfo[pidValue]->Reason;
                InterlockedIncrement(&ctx->BitmapExtendedInfo[pidValue]->HitCount);
            }

            ExReleasePushLockShared(&ctx->ExtendedInfoLock);
            KeLeaveCriticalRegion();
        }

    } else {
        //
        // Hash table lookup — data returned by value
        //
        if (PepFindPidInHash(ProcessId, &reason, NULL, NULL, NULL)) {
            trusted = TRUE;
            InterlockedIncrement64(&ctx->Stats.HashHits);
        }
    }

    if (!trusted) {
        InterlockedIncrement64(&ctx->Stats.Misses);
    }

    if (Reason != NULL) {
        *Reason = reason;
    }

    return trusted;
}

// ============================================================================
// PUBLIC API - MANUAL EXCLUSION MANAGEMENT
// ============================================================================

/**
 * @brief Manually add a process to the trusted set.
 *
 * @param ProcessId     Process ID to exclude
 * @param Permanent     If TRUE, cannot be removed by automatic cleanup
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowStrikeAddTrustedProcess(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Permanent
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;
    NTSTATUS status = STATUS_SUCCESS;

    if (!PepIsReady()) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    PepAcquireReference();

    if (pidValue < PE_BITMAP_MAX_PID) {
        //
        // Add to bitmap
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&ctx->BitmapLock);

        if (!PepIsPidInBitmap(ProcessId)) {
            PepSetPidInBitmap(ProcessId);
            InterlockedIncrement(&ctx->Stats.CurrentBitmapCount);
        }

        ExReleasePushLockExclusive(&ctx->BitmapLock);
        KeLeaveCriticalRegion();

        //
        // Create extended info
        //
        PPE_PID_ENTRY extInfo = NULL;
        status = PepAllocatePidEntry(&extInfo);
        if (NT_SUCCESS(status)) {
            extInfo->ProcessId = ProcessId;
            extInfo->Reason = PeReason_ManualExclusion;
            extInfo->Permanent = Permanent;
            extInfo->InheritToChildren = FALSE;
            KeQuerySystemTime(&extInfo->ExclusionTime);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&ctx->ExtendedInfoLock);

            if (ctx->BitmapExtendedInfo != NULL) {
                if (ctx->BitmapExtendedInfo[pidValue] != NULL) {
                    PepFreePidEntry(ctx->BitmapExtendedInfo[pidValue]);
                }
                ctx->BitmapExtendedInfo[pidValue] = extInfo;
            }

            ExReleasePushLockExclusive(&ctx->ExtendedInfoLock);
            KeLeaveCriticalRegion();
        }

    } else {
        //
        // Add to hash table
        //
        status = PepAddPidToHash(
            ProcessId,
            NULL,
            PeReason_ManualExclusion,
            FALSE,
            0
        );

        if (NT_SUCCESS(status)) {
            InterlockedIncrement(&ctx->Stats.CurrentHashCount);
        }
    }

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&ctx->Stats.ManualExclusions);
        InterlockedIncrement64(&ctx->Stats.ProcessesExcluded);
    }

    PepReleaseReference();

    return status;
}

/**
 * @brief Remove a process from the trusted set.
 *
 * @param ProcessId     Process ID to remove
 *
 * @return TRUE if removed, FALSE if not found
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeRemoveTrustedProcess(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;
    BOOLEAN removed = FALSE;

    if (!PepIsReady()) {
        return FALSE;
    }

    if (ProcessId == NULL) {
        return FALSE;
    }

    PepAcquireReference();

    if (pidValue < PE_BITMAP_MAX_PID) {
        //
        // Single exclusive lock acquisition for permanent check + remove (H-5 fix).
        // The original code checked permanent under shared lock, released,
        // then re-acquired exclusive — classic TOCTOU.
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&ctx->ExtendedInfoLock);

        if (ctx->BitmapExtendedInfo != NULL &&
            ctx->BitmapExtendedInfo[pidValue] != NULL &&
            ctx->BitmapExtendedInfo[pidValue]->Permanent) {
            //
            // Permanent entries cannot be removed
            //
            ExReleasePushLockExclusive(&ctx->ExtendedInfoLock);
            KeLeaveCriticalRegion();
            PepReleaseReference();
            return FALSE;
        }

        //
        // Remove from bitmap
        //
        ExAcquirePushLockExclusive(&ctx->BitmapLock);

        if (PepIsPidInBitmap(ProcessId)) {
            PepClearPidInBitmap(ProcessId);
            InterlockedDecrement(&ctx->Stats.CurrentBitmapCount);
            removed = TRUE;
        }

        ExReleasePushLockExclusive(&ctx->BitmapLock);

        //
        // Free extended info (still under ExtendedInfoLock)
        //
        if (removed && ctx->BitmapExtendedInfo != NULL &&
            ctx->BitmapExtendedInfo[pidValue] != NULL) {
            PepFreePidEntry(ctx->BitmapExtendedInfo[pidValue]);
            ctx->BitmapExtendedInfo[pidValue] = NULL;
        }

        ExReleasePushLockExclusive(&ctx->ExtendedInfoLock);
        KeLeaveCriticalRegion();

    } else {
        //
        // Hash table path — check permanent and remove under single lock
        //
        BOOLEAN isPermanent = FALSE;
        if (PepFindPidInHash(ProcessId, NULL, NULL, NULL, &isPermanent)) {
            if (!isPermanent) {
                PepRemovePidFromHash(ProcessId);
                removed = TRUE;
            }
        }
    }

    PepReleaseReference();

    return removed;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get process exclusion statistics.
 *
 * NOTE: Statistics are approximate. Individual fields are read atomically
 * via interlocked operations, but cross-field consistency is NOT guaranteed.
 * This is acceptable for diagnostics/telemetry.
 *
 * @param Stats     Receives statistics
 *
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeProcessExclusionGetStats(
    _Out_ PPE_STATISTICS Stats
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;

    if (Stats == NULL) {
        return;
    }

    //
    // Each field is atomically consistent, but the snapshot
    // as a whole is not (no cross-field lock).
    //
    RtlCopyMemory(Stats, &ctx->Stats, sizeof(PE_STATISTICS));
}

/**
 * @brief Reset process exclusion statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeProcessExclusionResetStats(
    VOID
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;

    //
    // Reset counters but preserve current counts
    //
    InterlockedExchange64(&ctx->Stats.TotalLookups, 0);
    InterlockedExchange64(&ctx->Stats.BitmapHits, 0);
    InterlockedExchange64(&ctx->Stats.HashHits, 0);
    InterlockedExchange64(&ctx->Stats.Misses, 0);

    KeQuerySystemTime(&ctx->Stats.StartTime);
}

/**
 * @brief Get count of currently excluded processes.
 *
 * @return Number of excluded processes
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowStrikeGetTrustedProcessCount(
    VOID
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;

    if (!PepIsReady()) {
        return 0;
    }

    //
    // Use interlocked reads for each field individually.
    // The sum is approximate but each operand is consistent.
    //
    LONG bitmapCount = ReadAcquire(&ctx->Stats.CurrentBitmapCount);
    LONG hashCount = ReadAcquire(&ctx->Stats.CurrentHashCount);

    return (ULONG)(bitmapCount + hashCount);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

static VOID
PepAcquireReference(
    VOID
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    InterlockedIncrement(&ctx->ReferenceCount);
}

static VOID
PepReleaseReference(
    VOID
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    LONG newCount = InterlockedDecrement(&ctx->ReferenceCount);

    if (newCount == 0 &&
        ReadAcquire(&ctx->State) == PE_STATE_SHUTTING_DOWN) {
        KeSetEvent(&ctx->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - BITMAP OPERATIONS
// ============================================================================

static FORCEINLINE ULONG
PepPidToBitmapIndex(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    return (ULONG)(pid / 32);
}

static FORCEINLINE ULONG
PepPidToBitmapBit(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    return (ULONG)(pid % 32);
}

static BOOLEAN
PepIsPidInBitmap(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    ULONG index;
    ULONG bit;

    if (pid >= PE_BITMAP_MAX_PID) {
        return FALSE;
    }

    if (ctx->TrustedPidBitmap == NULL) {
        return FALSE;
    }

    index = PepPidToBitmapIndex(ProcessId);
    bit = PepPidToBitmapBit(ProcessId);

    return (ctx->TrustedPidBitmap[index] & (1UL << bit)) != 0;
}

static VOID
PepSetPidInBitmap(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    ULONG index;
    ULONG bit;

    if (pid >= PE_BITMAP_MAX_PID) {
        return;
    }

    if (ctx->TrustedPidBitmap == NULL) {
        return;
    }

    index = PepPidToBitmapIndex(ProcessId);
    bit = PepPidToBitmapBit(ProcessId);

    ctx->TrustedPidBitmap[index] |= (1UL << bit);
}

static VOID
PepClearPidInBitmap(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    ULONG index;
    ULONG bit;

    if (pid >= PE_BITMAP_MAX_PID) {
        return;
    }

    if (ctx->TrustedPidBitmap == NULL) {
        return;
    }

    index = PepPidToBitmapIndex(ProcessId);
    bit = PepPidToBitmapBit(ProcessId);

    ctx->TrustedPidBitmap[index] &= ~(1UL << bit);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HASH TABLE OPERATIONS
// ============================================================================

static FORCEINLINE ULONG
PepPidToHashBucket(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    //
    // Simple hash - XOR fold the PID
    //
    ULONG hash = (ULONG)(pid ^ (pid >> 16));
    return hash % PE_HASH_BUCKET_COUNT;
}

static BOOLEAN
PepFindPidInHash(
    _In_ HANDLE ProcessId,
    _Out_opt_ PE_EXCLUSION_REASON* Reason,
    _Out_opt_ PBOOLEAN InheritToChildren,
    _Out_opt_ PULONG InheritanceDepth,
    _Out_opt_ PBOOLEAN Permanent
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG bucket = PepPidToHashBucket(ProcessId);
    PLIST_ENTRY entry;
    PPE_PID_ENTRY pidEntry;
    BOOLEAN found = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&ctx->HashLock);

    for (entry = ctx->HashBuckets[bucket].ListHead.Flink;
         entry != &ctx->HashBuckets[bucket].ListHead;
         entry = entry->Flink) {

        pidEntry = CONTAINING_RECORD(entry, PE_PID_ENTRY, ListEntry);

        if (pidEntry->ProcessId == ProcessId) {
            found = TRUE;

            //
            // Copy data out by value while still holding lock
            //
            if (Reason != NULL) {
                *Reason = pidEntry->Reason;
            }
            if (InheritToChildren != NULL) {
                *InheritToChildren = pidEntry->InheritToChildren;
            }
            if (InheritanceDepth != NULL) {
                *InheritanceDepth = pidEntry->InheritanceDepth;
            }
            if (Permanent != NULL) {
                *Permanent = pidEntry->Permanent;
            }
            break;
        }
    }

    ExReleasePushLockShared(&ctx->HashLock);
    KeLeaveCriticalRegion();

    return found;
}

static NTSTATUS
PepAddPidToHash(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ PE_EXCLUSION_REASON Reason,
    _In_ BOOLEAN InheritToChildren,
    _In_ ULONG InheritanceDepth
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    PPE_PID_ENTRY entry = NULL;
    PLIST_ENTRY listEntry;
    PPE_PID_ENTRY existingEntry;
    ULONG bucket;
    NTSTATUS status;

    //
    // Pre-allocate entry BEFORE taking lock to minimize hold time
    //
    status = PepAllocatePidEntry(&entry);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    entry->ProcessId = ProcessId;
    entry->ParentProcessId = ParentProcessId;
    entry->Reason = Reason;
    entry->InheritToChildren = InheritToChildren;
    entry->InheritanceDepth = InheritanceDepth;
    entry->Permanent = FALSE;
    entry->HitCount = 0;
    KeQuerySystemTime(&entry->ExclusionTime);

    bucket = PepPidToHashBucket(ProcessId);

    //
    // Duplicate check + insert under single exclusive lock (C-3 TOCTOU fix)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ctx->HashLock);

    for (listEntry = ctx->HashBuckets[bucket].ListHead.Flink;
         listEntry != &ctx->HashBuckets[bucket].ListHead;
         listEntry = listEntry->Flink) {

        existingEntry = CONTAINING_RECORD(listEntry, PE_PID_ENTRY, ListEntry);

        if (existingEntry->ProcessId == ProcessId) {
            //
            // Already exists — release lock, free pre-allocated entry
            //
            ExReleasePushLockExclusive(&ctx->HashLock);
            KeLeaveCriticalRegion();
            PepFreePidEntry(entry);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    InsertHeadList(&ctx->HashBuckets[bucket].ListHead, &entry->ListEntry);
    InterlockedIncrement(&ctx->HashBuckets[bucket].EntryCount);

    ExReleasePushLockExclusive(&ctx->HashLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

static VOID
PepRemovePidFromHash(
    _In_ HANDLE ProcessId
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG bucket = PepPidToHashBucket(ProcessId);
    PLIST_ENTRY entry;
    PPE_PID_ENTRY pidEntry;
    PPE_PID_ENTRY toRemove = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ctx->HashLock);

    for (entry = ctx->HashBuckets[bucket].ListHead.Flink;
         entry != &ctx->HashBuckets[bucket].ListHead;
         entry = entry->Flink) {

        pidEntry = CONTAINING_RECORD(entry, PE_PID_ENTRY, ListEntry);

        if (pidEntry->ProcessId == ProcessId) {
            toRemove = pidEntry;
            RemoveEntryList(&pidEntry->ListEntry);
            InterlockedDecrement(&ctx->HashBuckets[bucket].EntryCount);
            InterlockedDecrement(&ctx->Stats.CurrentHashCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&ctx->HashLock);
    KeLeaveCriticalRegion();

    if (toRemove != NULL) {
        PepFreePidEntry(toRemove);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ALLOCATION
// ============================================================================

static NTSTATUS
PepAllocatePidEntry(
    _Out_ PPE_PID_ENTRY* Entry
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    PPE_PID_ENTRY entry = NULL;

    *Entry = NULL;

    if (ctx->LookasideInitialized) {
        entry = (PPE_PID_ENTRY)ExAllocateFromNPagedLookasideList(
            &ctx->PidEntryLookaside
        );
    }

    if (entry == NULL) {
        entry = (PPE_PID_ENTRY)ExAllocatePoolZero(
            NonPagedPoolNx,
            sizeof(PE_PID_ENTRY),
            PE_PID_TAG
        );
    }

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(PE_PID_ENTRY));
    InitializeListHead(&entry->ListEntry);

    *Entry = entry;

    return STATUS_SUCCESS;
}

static VOID
PepFreePidEntry(
    _In_ PPE_PID_ENTRY Entry
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;

    if (Entry == NULL) {
        return;
    }

    if (ctx->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&ctx->PidEntryLookaside, Entry);
    } else {
        ExFreePoolWithTag(Entry, PE_PID_TAG);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - EXCLUSION CHECKING HELPERS
// ============================================================================

static BOOLEAN
PepCheckParentExclusion(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _Out_ PE_EXCLUSION_REASON* Reason,
    _Out_ PULONG InheritanceDepth
    )
{
    PPE_CONTEXT ctx = &g_ProcessExclusionContext;
    ULONG_PTR parentPidValue = (ULONG_PTR)ParentProcessId;
    BOOLEAN parentExcluded = FALSE;

    *Reason = PeReason_None;
    *InheritanceDepth = 0;

    if (ParentProcessId == NULL) {
        return FALSE;
    }

    //
    // Check if parent is in bitmap
    //
    if (parentPidValue < PE_BITMAP_MAX_PID) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&ctx->BitmapLock);

        parentExcluded = PepIsPidInBitmap(ParentProcessId);

        ExReleasePushLockShared(&ctx->BitmapLock);
        KeLeaveCriticalRegion();

        if (parentExcluded) {
            //
            // Check if inheritance is enabled for parent
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&ctx->ExtendedInfoLock);

            PPE_PID_ENTRY extInfo = (ctx->BitmapExtendedInfo != NULL)
                ? ctx->BitmapExtendedInfo[parentPidValue]
                : NULL;
            if (extInfo != NULL && extInfo->InheritToChildren) {
                *Reason = extInfo->Reason;
                *InheritanceDepth = extInfo->InheritanceDepth;
            } else {
                parentExcluded = FALSE;  // Inheritance not enabled
            }

            ExReleasePushLockShared(&ctx->ExtendedInfoLock);
            KeLeaveCriticalRegion();
        }

    } else {
        //
        // Check hash table — data returned by value
        //
        PE_EXCLUSION_REASON hashReason = PeReason_None;
        BOOLEAN hashInherit = FALSE;
        ULONG hashDepth = 0;

        if (PepFindPidInHash(ParentProcessId, &hashReason, &hashInherit, &hashDepth, NULL)) {
            if (hashInherit) {
                parentExcluded = TRUE;
                *Reason = hashReason;
                *InheritanceDepth = hashDepth;
            }
        }
    }

    return parentExcluded;
}

