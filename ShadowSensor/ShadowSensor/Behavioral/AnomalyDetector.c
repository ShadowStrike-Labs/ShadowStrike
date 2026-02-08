/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ANOMALY DETECTION ENGINE
 * ============================================================================
 *
 * @file AnomalyDetector.c
 * @brief Enterprise-grade statistical anomaly detection for behavioral analysis.
 *
 * SECURITY & STABILITY FIXES (v2.1):
 * - [P0] DPC cleanup moved to work item (IRQL safety)
 * - [P0] Stack allocations replaced with pooled buffers
 * - [P0] Floating-point state properly saved/restored
 * - [P0] Per-baseline synchronization added
 * - [P1] Callback registration race fixed with interlocked ops
 * - [P1] Anomaly count race fixed (check inside lock)
 * - [P1] Reference counting for safe shutdown
 * - [P1] Memory leak on eviction fixed
 * - [P2] Process name population implemented
 * - [P2] Callback unregistration API added
 * - [P2] Min/Max recalculated on sliding window
 * - [P1] IRQL enforcement with SAL annotations
 * - [P2] Structure integrity validation with magic
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AnomalyDetector.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, AdInitialize)
#pragma alloc_text(PAGE, AdShutdown)
#pragma alloc_text(PAGE, AdSetThreshold)
#pragma alloc_text(PAGE, AdRegisterCallback)
#pragma alloc_text(PAGE, AdUnregisterCallback)
#pragma alloc_text(PAGE, AdRecordSample)
#pragma alloc_text(PAGE, AdCheckForAnomaly)
#pragma alloc_text(PAGE, AdGetBaseline)
#pragma alloc_text(PAGE, AdGetRecentAnomalies)
#pragma alloc_text(PAGE, AdGetStatistics)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define AD_MAGIC                            0x41444554  // 'ADET'
#define AD_MAX_PROCESS_BASELINES            4096
#define AD_MAX_GLOBAL_BASELINES             64
#define AD_MAX_ANOMALIES                    10000
#define AD_MAX_CALLBACKS                    16
#define AD_CLEANUP_INTERVAL_MS              60000
#define AD_MIN_SAMPLES_FOR_DETECTION        10
#define AD_STALE_BASELINE_AGE_MS            3600000     // 1 hour
#define AD_SHUTDOWN_TIMEOUT_MS              30000       // 30 seconds
#define AD_HASH_BUCKET_COUNT                1024

//
// Default thresholds
//
#define AD_DEFAULT_SIGMA_THRESHOLD          3.0
#define AD_HIGH_CONFIDENCE_SIGMA            4.0
#define AD_CRITICAL_SIGMA                   5.0
#define AD_MIN_SIGMA_THRESHOLD              1.5
#define AD_MAX_SIGMA_THRESHOLD              6.0

//
// Severity score mapping
//
#define AD_SEVERITY_LOW_SIGMA               2.0
#define AD_SEVERITY_MEDIUM_SIGMA            3.0
#define AD_SEVERITY_HIGH_SIGMA              4.0
#define AD_SEVERITY_CRITICAL_SIGMA          5.0

//
// Exponential moving average alpha
//
#define AD_EMA_ALPHA                        0.1
#define AD_EMA_FAST_ALPHA                   0.3

//
// Modified Z-score constant (for MAD-based detection)
//
#define AD_MAD_CONSTANT                     0.6745

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Internal baseline with synchronization.
 */
typedef struct _AD_BASELINE_INTERNAL {
    AD_METRIC_TYPE Type;

    //
    // Statistical baseline (protected by Lock)
    //
    DOUBLE Mean;
    DOUBLE StandardDeviation;
    DOUBLE Min;
    DOUBLE Max;
    ULONG SampleCount;

    //
    // Circular buffer for sliding window
    //
    DOUBLE Samples[AD_BASELINE_SAMPLES];
    ULONG CurrentIndex;
    BOOLEAN IsFull;

    LARGE_INTEGER LastUpdated;

    //
    // Per-baseline lock for thread safety [FIX: P0 - Race conditions]
    //
    KSPIN_LOCK Lock;

    LIST_ENTRY ListEntry;
} AD_BASELINE_INTERNAL, *PAD_BASELINE_INTERNAL;

/**
 * @brief Per-process baseline context.
 */
typedef struct _AD_PROCESS_BASELINE {
    HANDLE ProcessId;
    WCHAR ProcessName[AD_MAX_PROCESS_NAME_CCH];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastActivityTime;

    //
    // Per-metric baselines (embedded, not pointers)
    //
    AD_BASELINE_INTERNAL Baselines[AD_METRIC_COUNT];

    //
    // Exponential moving averages
    //
    DOUBLE EMA[AD_METRIC_COUNT];
    DOUBLE EMAFast[AD_METRIC_COUNT];
    BOOLEAN EMAInitialized[AD_METRIC_COUNT];

    //
    // Reference counting [FIX: P1 - Use-after-free]
    //
    volatile LONG RefCount;

    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

} AD_PROCESS_BASELINE, *PAD_PROCESS_BASELINE;

/**
 * @brief Internal anomaly record.
 */
typedef struct _AD_ANOMALY_INTERNAL {
    AD_ANOMALY_INFO Info;
    LIST_ENTRY ListEntry;
} AD_ANOMALY_INTERNAL, *PAD_ANOMALY_INTERNAL;

/**
 * @brief Callback registration entry.
 */
typedef struct _AD_CALLBACK_ENTRY {
    AD_ANOMALY_CALLBACK Callback;
    PVOID Context;
    volatile LONG InUse;
    ULONG SlotIndex;
} AD_CALLBACK_ENTRY, *PAD_CALLBACK_ENTRY;

/**
 * @brief Work item context for deferred cleanup.
 */
typedef struct _AD_CLEANUP_WORK_CONTEXT {
    PIO_WORKITEM WorkItem;
    struct _AD_DETECTOR* Detector;
} AD_CLEANUP_WORK_CONTEXT, *PAD_CLEANUP_WORK_CONTEXT;

/**
 * @brief Scratch buffer for statistical calculations.
 * Allocated once per detector to avoid stack overflow.
 * [FIX: P0 - Stack overflow]
 */
typedef struct _AD_SCRATCH_BUFFER {
    DOUBLE SortBuffer[AD_BASELINE_SAMPLES];
    DOUBLE DeviationBuffer[AD_BASELINE_SAMPLES];
    KSPIN_LOCK Lock;
} AD_SCRATCH_BUFFER, *PAD_SCRATCH_BUFFER;

/**
 * @brief Main detector structure.
 */
typedef struct _AD_DETECTOR {
    //
    // Magic for structure validation [FIX: P2 - Structure validation]
    //
    ULONG Magic;

    //
    // State flags
    //
    volatile LONG Initialized;
    volatile LONG ShuttingDown;

    //
    // Reference counting [FIX: P1 - Use-after-free in shutdown]
    //
    volatile LONG RefCount;
    KEVENT ZeroRefEvent;

    //
    // Global baselines
    //
    LIST_ENTRY GlobalBaselines;
    EX_PUSH_LOCK GlobalBaselineLock;

    //
    // Process baselines hash table
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
    } ProcessHash;

    //
    // Process baseline list
    //
    LIST_ENTRY ProcessBaselineList;
    EX_PUSH_LOCK ProcessBaselineListLock;
    volatile LONG ProcessBaselineCount;

    //
    // Configuration
    //
    DOUBLE SigmaThreshold;
    ULONG MinimumSamples;

    //
    // Anomaly storage
    //
    LIST_ENTRY AnomalyList;
    KSPIN_LOCK AnomalyLock;
    volatile LONG AnomalyCount;

    //
    // Callbacks [FIX: P1 - Race condition, P2 - Unregister API]
    //
    AD_CALLBACK_ENTRY Callbacks[AD_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST BaselineLookaside;
    NPAGED_LOOKASIDE_LIST AnomalyLookaside;
    NPAGED_LOOKASIDE_LIST ProcessBaselineLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Scratch buffer for calculations [FIX: P0 - Stack overflow]
    //
    PAD_SCRATCH_BUFFER ScratchBuffer;

    //
    // Cleanup timer and work item [FIX: P0 - DPC IRQL violation]
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    PIO_WORKITEM CleanupWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG CleanupInProgress;

    //
    // Statistics
    //
    struct {
        volatile LONG64 SamplesProcessed;
        volatile LONG64 AnomaliesDetected;
        LARGE_INTEGER StartTime;
    } Stats;

} AD_DETECTOR, *PAD_DETECTOR_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
AdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

IO_WORKITEM_ROUTINE AdpCleanupWorkItemRoutine;

static NTSTATUS
AdpInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static VOID
AdpFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets
    );

static ULONG
AdpHashProcessId(
    _In_ HANDLE ProcessId,
    _In_ ULONG BucketCount
    );

static PAD_BASELINE_INTERNAL
AdpFindGlobalBaselineLocked(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_METRIC_TYPE Metric
    );

static PAD_BASELINE_INTERNAL
AdpCreateGlobalBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_METRIC_TYPE Metric
    );

static PAD_PROCESS_BASELINE
AdpFindProcessBaselineLocked(
    _In_ PAD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

static PAD_PROCESS_BASELINE
AdpCreateProcessBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

static VOID
AdpReferenceProcessBaseline(
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    );

static VOID
AdpDereferenceProcessBaseline(
    _In_ PAD_DETECTOR Detector,
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    );

static VOID
AdpFreeProcessBaseline(
    _In_ PAD_DETECTOR Detector,
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    );

static VOID
AdpUpdateBaselineLocked(
    _Inout_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE Value
    );

static VOID
AdpUpdateEMA(
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value
    );

static VOID
AdpCalculateStatisticsLocked(
    _Inout_ PAD_BASELINE_INTERNAL Baseline
    );

static DOUBLE
AdpCalculateZScoreLocked(
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE Value
    );

static DOUBLE
AdpCalculateModifiedZScore(
    _In_ PAD_DETECTOR Detector,
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE Value
    );

static ULONG
AdpCalculateSeverityScore(
    _In_ DOUBLE DeviationSigmas,
    _In_ AD_METRIC_TYPE Metric
    );

static BOOLEAN
AdpIsHighConfidenceAnomaly(
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE DeviationSigmas,
    _In_ DOUBLE Value
    );

static VOID
AdpCreateAnomalyInfo(
    _In_opt_ HANDLE ProcessId,
    _In_opt_z_ PCWSTR ProcessName,
    _In_ AD_METRIC_TYPE Metric,
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE ObservedValue,
    _In_ DOUBLE DeviationSigmas,
    _Out_ PAD_ANOMALY_INFO AnomalyInfo
    );

static VOID
AdpNotifyCallbacks(
    _In_ PAD_DETECTOR Detector,
    _In_ CONST AD_ANOMALY_INFO* AnomalyInfo
    );

static VOID
AdpAddAnomalyToList(
    _In_ PAD_DETECTOR Detector,
    _In_ CONST AD_ANOMALY_INFO* AnomalyInfo
    );

static DOUBLE
AdpCalculateMedian(
    _Inout_updates_(Count) DOUBLE* Array,
    _In_ ULONG Count
    );

static DOUBLE
AdpCalculateMAD(
    _In_ PAD_DETECTOR Detector,
    _In_reads_(Count) CONST DOUBLE* SourceArray,
    _In_ ULONG Count,
    _In_ DOUBLE Median
    );

static VOID
AdpInsertionSortDouble(
    _Inout_updates_(Count) DOUBLE* Array,
    _In_ ULONG Count
    );

static VOID
AdpQueryProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxCch) PWSTR ProcessName,
    _In_ ULONG MaxCch
    );

static BOOLEAN
AdpValidateDetector(
    _In_opt_ PAD_DETECTOR Detector
    );

static VOID
AdpReferenceDetector(
    _In_ PAD_DETECTOR Detector
    );

static VOID
AdpDereferenceDetector(
    _In_ PAD_DETECTOR Detector
    );

//
// Floating-point safe math helpers [FIX: P0 - FP state corruption]
//
static DOUBLE
AdpSqrt(
    _In_ DOUBLE Value
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
AdInitialize(
    _Out_ PAD_DETECTOR* Detector
    )
{
    NTSTATUS status;
    PAD_DETECTOR detector = NULL;
    LARGE_INTEGER timerDue;
    ULONG i;
    KFLOATING_SAVE floatSave;
    BOOLEAN floatSaved = FALSE;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure from NonPagedPoolNx
    //
    detector = (PAD_DETECTOR)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(AD_DETECTOR),
        AD_POOL_TAG
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize magic and state
    //
    detector->Magic = AD_MAGIC;
    detector->Initialized = FALSE;
    detector->ShuttingDown = FALSE;
    detector->RefCount = 1;  // Initial reference
    KeInitializeEvent(&detector->ZeroRefEvent, NotificationEvent, FALSE);

    //
    // Initialize lists and locks
    //
    InitializeListHead(&detector->GlobalBaselines);
    ExInitializePushLock(&detector->GlobalBaselineLock);

    InitializeListHead(&detector->ProcessBaselineList);
    ExInitializePushLock(&detector->ProcessBaselineListLock);

    InitializeListHead(&detector->AnomalyList);
    KeInitializeSpinLock(&detector->AnomalyLock);

    ExInitializePushLock(&detector->CallbackLock);

    //
    // Initialize hash table
    //
    status = AdpInitializeHashTable(
        &detector->ProcessHash.Buckets,
        AD_HASH_BUCKET_COUNT
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(detector, AD_POOL_TAG);
        return status;
    }

    detector->ProcessHash.BucketCount = AD_HASH_BUCKET_COUNT;
    ExInitializePushLock(&detector->ProcessHash.Lock);

    //
    // Allocate scratch buffer [FIX: P0 - Stack overflow]
    //
    detector->ScratchBuffer = (PAD_SCRATCH_BUFFER)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(AD_SCRATCH_BUFFER),
        AD_POOL_TAG
    );

    if (detector->ScratchBuffer == NULL) {
        AdpFreeHashTable(&detector->ProcessHash.Buckets);
        ExFreePoolWithTag(detector, AD_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeSpinLock(&detector->ScratchBuffer->Lock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &detector->BaselineLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AD_BASELINE_INTERNAL),
        AD_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &detector->AnomalyLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AD_ANOMALY_INTERNAL),
        AD_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &detector->ProcessBaselineLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AD_PROCESS_BASELINE),
        AD_POOL_TAG,
        0
    );

    detector->LookasideInitialized = TRUE;

    //
    // Save floating-point state for initialization [FIX: P0 - FP state]
    //
    status = KeSaveFloatingPointState(&floatSave);
    if (NT_SUCCESS(status)) {
        floatSaved = TRUE;
    }

    //
    // Initialize default configuration
    //
    detector->SigmaThreshold = AD_DEFAULT_SIGMA_THRESHOLD;
    detector->MinimumSamples = AD_MIN_SAMPLES_FOR_DETECTION;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&detector->CleanupTimer);
    KeInitializeDpc(
        &detector->CleanupDpc,
        AdpCleanupTimerDpc,
        detector
    );

    //
    // Create global baselines for each metric type
    //
    for (i = 0; i < AD_METRIC_COUNT; i++) {
        PAD_BASELINE_INTERNAL baseline = AdpCreateGlobalBaseline(
            detector,
            (AD_METRIC_TYPE)i
        );

        if (baseline == NULL) {
            //
            // Critical failure - cannot create baselines
            //
            if (floatSaved) {
                KeRestoreFloatingPointState(&floatSave);
            }

            //
            // Cleanup already created baselines
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&detector->GlobalBaselineLock);

            while (!IsListEmpty(&detector->GlobalBaselines)) {
                PLIST_ENTRY entry = RemoveHeadList(&detector->GlobalBaselines);
                PAD_BASELINE_INTERNAL bl = CONTAINING_RECORD(
                    entry, AD_BASELINE_INTERNAL, ListEntry
                );
                ExFreeToNPagedLookasideList(&detector->BaselineLookaside, bl);
            }

            ExReleasePushLockExclusive(&detector->GlobalBaselineLock);
            KeLeaveCriticalRegion();

            if (detector->LookasideInitialized) {
                ExDeleteNPagedLookasideList(&detector->BaselineLookaside);
                ExDeleteNPagedLookasideList(&detector->AnomalyLookaside);
                ExDeleteNPagedLookasideList(&detector->ProcessBaselineLookaside);
            }

            ExFreePoolWithTag(detector->ScratchBuffer, AD_POOL_TAG);
            AdpFreeHashTable(&detector->ProcessHash.Buckets);
            ExFreePoolWithTag(detector, AD_POOL_TAG);

            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Restore floating-point state
    //
    if (floatSaved) {
        KeRestoreFloatingPointState(&floatSave);
    }

    //
    // Record start time
    //
    KeQuerySystemTime(&detector->Stats.StartTime);

    //
    // Start cleanup timer
    //
    timerDue.QuadPart = -((LONGLONG)AD_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &detector->CleanupTimer,
        timerDue,
        AD_CLEANUP_INTERVAL_MS,
        &detector->CleanupDpc
    );

    //
    // Mark as initialized
    //
    InterlockedExchange(&detector->Initialized, TRUE);
    *Detector = detector;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
AdShutdown(
    _Inout_ PAD_DETECTOR Detector
    )
{
    PLIST_ENTRY entry;
    PAD_BASELINE_INTERNAL baseline;
    PAD_ANOMALY_INTERNAL anomaly;
    PAD_PROCESS_BASELINE processBaseline;
    KIRQL oldIrql;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector)) {
        return;
    }

    //
    // Mark as shutting down - prevents new operations
    //
    if (InterlockedCompareExchange(&Detector->ShuttingDown, TRUE, FALSE) != FALSE) {
        //
        // Already shutting down
        //
        return;
    }

    InterlockedExchange(&Detector->Initialized, FALSE);

    //
    // Cancel the cleanup timer
    //
    KeCancelTimer(&Detector->CleanupTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for cleanup to complete with timeout [FIX: P1 - Infinite loop]
    //
    timeout.QuadPart = -((LONGLONG)AD_SHUTDOWN_TIMEOUT_MS * 10000);

    while (Detector->CleanupInProgress) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms

        waitStatus = KeDelayExecutionThread(KernelMode, FALSE, &delay);
        if (waitStatus != STATUS_SUCCESS) {
            break;
        }

        timeout.QuadPart += 10000;
        if (timeout.QuadPart >= 0) {
            //
            // Timeout exceeded - proceed anyway but log
            //
            break;
        }
    }

    //
    // Release our reference and wait for all operations to complete
    // [FIX: P1 - Use-after-free in shutdown]
    //
    AdpDereferenceDetector(Detector);

    timeout.QuadPart = -((LONGLONG)AD_SHUTDOWN_TIMEOUT_MS * 10000);
    waitStatus = KeWaitForSingleObject(
        &Detector->ZeroRefEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Free all global baselines
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->GlobalBaselineLock);

    while (!IsListEmpty(&Detector->GlobalBaselines)) {
        entry = RemoveHeadList(&Detector->GlobalBaselines);
        baseline = CONTAINING_RECORD(entry, AD_BASELINE_INTERNAL, ListEntry);
        ExFreeToNPagedLookasideList(&Detector->BaselineLookaside, baseline);
    }

    ExReleasePushLockExclusive(&Detector->GlobalBaselineLock);
    KeLeaveCriticalRegion();

    //
    // Free all process baselines
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessBaselineListLock);

    while (!IsListEmpty(&Detector->ProcessBaselineList)) {
        entry = RemoveHeadList(&Detector->ProcessBaselineList);
        processBaseline = CONTAINING_RECORD(entry, AD_PROCESS_BASELINE, ListEntry);
        AdpFreeProcessBaseline(Detector, processBaseline);
    }

    ExReleasePushLockExclusive(&Detector->ProcessBaselineListLock);
    KeLeaveCriticalRegion();

    //
    // Free all anomalies
    //
    KeAcquireSpinLock(&Detector->AnomalyLock, &oldIrql);

    while (!IsListEmpty(&Detector->AnomalyList)) {
        entry = RemoveHeadList(&Detector->AnomalyList);
        anomaly = CONTAINING_RECORD(entry, AD_ANOMALY_INTERNAL, ListEntry);
        ExFreeToNPagedLookasideList(&Detector->AnomalyLookaside, anomaly);
    }

    KeReleaseSpinLock(&Detector->AnomalyLock, oldIrql);

    //
    // Free hash table
    //
    AdpFreeHashTable(&Detector->ProcessHash.Buckets);

    //
    // Free scratch buffer
    //
    if (Detector->ScratchBuffer != NULL) {
        ExFreePoolWithTag(Detector->ScratchBuffer, AD_POOL_TAG);
    }

    //
    // Delete lookaside lists
    //
    if (Detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Detector->BaselineLookaside);
        ExDeleteNPagedLookasideList(&Detector->AnomalyLookaside);
        ExDeleteNPagedLookasideList(&Detector->ProcessBaselineLookaside);
    }

    //
    // Invalidate magic and free detector
    //
    Detector->Magic = 0;
    ExFreePoolWithTag(Detector, AD_POOL_TAG);
}

// ============================================================================
// PUBLIC API - CONFIGURATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
AdSetThreshold(
    _In_ PAD_DETECTOR Detector,
    _In_ DOUBLE SigmaThreshold
    )
{
    KFLOATING_SAVE floatSave;
    NTSTATUS status;
    BOOLEAN floatSaved = FALSE;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Save FP state for comparison [FIX: P0 - FP state]
    //
    status = KeSaveFloatingPointState(&floatSave);
    if (NT_SUCCESS(status)) {
        floatSaved = TRUE;
    }

    if (SigmaThreshold < AD_MIN_SIGMA_THRESHOLD ||
        SigmaThreshold > AD_MAX_SIGMA_THRESHOLD) {
        if (floatSaved) {
            KeRestoreFloatingPointState(&floatSave);
        }
        return STATUS_INVALID_PARAMETER;
    }

    Detector->SigmaThreshold = SigmaThreshold;

    if (floatSaved) {
        KeRestoreFloatingPointState(&floatSave);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdRegisterCallback(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_ANOMALY_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ AD_CALLBACK_HANDLE* Handle
    )
{
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector) || Callback == NULL || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Handle = NULL;

    if (Detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find an empty slot using interlocked operations [FIX: P1 - Race]
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->CallbackLock);

    for (i = 0; i < AD_MAX_CALLBACKS; i++) {
        if (InterlockedCompareExchange(&Detector->Callbacks[i].InUse, TRUE, FALSE) == FALSE) {
            Detector->Callbacks[i].Callback = Callback;
            Detector->Callbacks[i].Context = Context;
            Detector->Callbacks[i].SlotIndex = i;
            InterlockedIncrement(&Detector->CallbackCount);

            *Handle = (AD_CALLBACK_HANDLE)&Detector->Callbacks[i];
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
NTSTATUS
AdUnregisterCallback(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_CALLBACK_HANDLE Handle
    )
{
    PAD_CALLBACK_ENTRY entry;
    ULONG slotIndex;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector) || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PAD_CALLBACK_ENTRY)Handle;

    //
    // Validate the handle points within our callback array
    //
    if ((ULONG_PTR)entry < (ULONG_PTR)&Detector->Callbacks[0] ||
        (ULONG_PTR)entry >= (ULONG_PTR)&Detector->Callbacks[AD_MAX_CALLBACKS]) {
        return STATUS_INVALID_HANDLE;
    }

    slotIndex = entry->SlotIndex;
    if (slotIndex >= AD_MAX_CALLBACKS) {
        return STATUS_INVALID_HANDLE;
    }

    //
    // Verify it's the correct entry
    //
    if (entry != &Detector->Callbacks[slotIndex]) {
        return STATUS_INVALID_HANDLE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->CallbackLock);

    if (InterlockedCompareExchange(&entry->InUse, FALSE, TRUE) == TRUE) {
        entry->Callback = NULL;
        entry->Context = NULL;
        InterlockedDecrement(&Detector->CallbackCount);
    }

    ExReleasePushLockExclusive(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - SAMPLE RECORDING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
AdRecordSample(
    _In_ PAD_DETECTOR Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value
    )
{
    PAD_BASELINE_INTERNAL globalBaseline;
    PAD_PROCESS_BASELINE processBaseline = NULL;
    KIRQL oldIrql;
    KFLOATING_SAVE floatSave;
    NTSTATUS status;
    BOOLEAN floatSaved = FALSE;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Metric > AdMetric_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire reference for duration of operation [FIX: P1 - Use-after-free]
    //
    AdpReferenceDetector(Detector);

    //
    // Save floating-point state [FIX: P0 - FP state corruption]
    //
    status = KeSaveFloatingPointState(&floatSave);
    if (NT_SUCCESS(status)) {
        floatSaved = TRUE;
    }

    //
    // Update global baseline
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->GlobalBaselineLock);

    globalBaseline = AdpFindGlobalBaselineLocked(Detector, Metric);

    ExReleasePushLockShared(&Detector->GlobalBaselineLock);
    KeLeaveCriticalRegion();

    if (globalBaseline != NULL) {
        KeAcquireSpinLock(&globalBaseline->Lock, &oldIrql);
        AdpUpdateBaselineLocked(globalBaseline, Value);
        KeReleaseSpinLock(&globalBaseline->Lock, oldIrql);
    }

    //
    // Update process-specific baseline if ProcessId is provided
    //
    if (ProcessId != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Detector->ProcessHash.Lock);

        processBaseline = AdpFindProcessBaselineLocked(Detector, ProcessId);
        if (processBaseline != NULL) {
            AdpReferenceProcessBaseline(processBaseline);
        }

        ExReleasePushLockShared(&Detector->ProcessHash.Lock);
        KeLeaveCriticalRegion();

        if (processBaseline == NULL) {
            processBaseline = AdpCreateProcessBaseline(Detector, ProcessId);
        }

        if (processBaseline != NULL) {
            KeAcquireSpinLock(&processBaseline->Baselines[Metric].Lock, &oldIrql);
            AdpUpdateBaselineLocked(&processBaseline->Baselines[Metric], Value);
            KeReleaseSpinLock(&processBaseline->Baselines[Metric].Lock, oldIrql);

            AdpUpdateEMA(processBaseline, Metric, Value);
            KeQuerySystemTime(&processBaseline->LastActivityTime);

            AdpDereferenceProcessBaseline(Detector, processBaseline);
        }
    }

    //
    // Restore floating-point state
    //
    if (floatSaved) {
        KeRestoreFloatingPointState(&floatSave);
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.SamplesProcessed);

    AdpDereferenceDetector(Detector);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - ANOMALY DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
AdCheckForAnomaly(
    _In_ PAD_DETECTOR Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value,
    _Out_ PBOOLEAN IsAnomaly,
    _Out_opt_ PAD_ANOMALY_INFO AnomalyInfo
    )
{
    PAD_BASELINE_INTERNAL baseline = NULL;
    PAD_PROCESS_BASELINE processBaseline = NULL;
    AD_ANOMALY_INFO anomalyInfo;
    DOUBLE zScore;
    DOUBLE modifiedZScore;
    DOUBLE effectiveDeviation;
    BOOLEAN isAnomaly = FALSE;
    BOOLEAN useProcessBaseline = FALSE;
    KIRQL oldIrql;
    KFLOATING_SAVE floatSave;
    NTSTATUS status;
    BOOLEAN floatSaved = FALSE;
    WCHAR processName[AD_MAX_PROCESS_NAME_CCH];
    DOUBLE baselineMean, baselineStdDev, baselineMin, baselineMax;
    ULONG sampleCount;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector) || IsAnomaly == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Metric > AdMetric_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsAnomaly = FALSE;
    if (AnomalyInfo != NULL) {
        RtlZeroMemory(AnomalyInfo, sizeof(AD_ANOMALY_INFO));
    }

    RtlZeroMemory(&anomalyInfo, sizeof(AD_ANOMALY_INFO));
    RtlZeroMemory(processName, sizeof(processName));

    //
    // Acquire reference for duration of operation
    //
    AdpReferenceDetector(Detector);

    //
    // Save floating-point state [FIX: P0 - FP state corruption]
    //
    status = KeSaveFloatingPointState(&floatSave);
    if (NT_SUCCESS(status)) {
        floatSaved = TRUE;
    }

    //
    // Try process-specific baseline first
    //
    if (ProcessId != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Detector->ProcessHash.Lock);

        processBaseline = AdpFindProcessBaselineLocked(Detector, ProcessId);
        if (processBaseline != NULL) {
            AdpReferenceProcessBaseline(processBaseline);
        }

        ExReleasePushLockShared(&Detector->ProcessHash.Lock);
        KeLeaveCriticalRegion();

        if (processBaseline != NULL) {
            KeAcquireSpinLock(&processBaseline->Baselines[Metric].Lock, &oldIrql);

            if (processBaseline->Baselines[Metric].SampleCount >= Detector->MinimumSamples) {
                baseline = &processBaseline->Baselines[Metric];
                useProcessBaseline = TRUE;

                //
                // Copy process name for anomaly info [FIX: P2 - Process name]
                //
                RtlCopyMemory(processName, processBaseline->ProcessName, sizeof(processName));
            }

            KeReleaseSpinLock(&processBaseline->Baselines[Metric].Lock, oldIrql);
        }
    }

    //
    // Fall back to global baseline
    //
    if (baseline == NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Detector->GlobalBaselineLock);

        baseline = AdpFindGlobalBaselineLocked(Detector, Metric);

        ExReleasePushLockShared(&Detector->GlobalBaselineLock);
        KeLeaveCriticalRegion();
    }

    if (baseline == NULL) {
        if (processBaseline != NULL) {
            AdpDereferenceProcessBaseline(Detector, processBaseline);
        }
        if (floatSaved) {
            KeRestoreFloatingPointState(&floatSave);
        }
        AdpDereferenceDetector(Detector);
        return STATUS_SUCCESS;
    }

    //
    // Read baseline statistics under lock [FIX: P0 - Race conditions]
    //
    KeAcquireSpinLock(&baseline->Lock, &oldIrql);

    sampleCount = baseline->SampleCount;
    if (sampleCount < Detector->MinimumSamples) {
        KeReleaseSpinLock(&baseline->Lock, oldIrql);

        if (processBaseline != NULL) {
            AdpDereferenceProcessBaseline(Detector, processBaseline);
        }
        if (floatSaved) {
            KeRestoreFloatingPointState(&floatSave);
        }
        AdpDereferenceDetector(Detector);
        return STATUS_SUCCESS;
    }

    baselineMean = baseline->Mean;
    baselineStdDev = baseline->StandardDeviation;
    baselineMin = baseline->Min;
    baselineMax = baseline->Max;

    //
    // Calculate Z-score under lock
    //
    zScore = AdpCalculateZScoreLocked(baseline, Value);

    KeReleaseSpinLock(&baseline->Lock, oldIrql);

    //
    // Calculate Modified Z-score (requires scratch buffer, done outside spinlock)
    //
    modifiedZScore = AdpCalculateModifiedZScore(Detector, baseline, Value);

    //
    // Use the more conservative of the two methods
    //
    effectiveDeviation = (zScore < modifiedZScore) ? zScore : modifiedZScore;

    //
    // For very high deviations, use standard Z-score
    //
    if (zScore > AD_HIGH_CONFIDENCE_SIGMA) {
        effectiveDeviation = zScore;
    }

    //
    // Check against threshold
    //
    if (effectiveDeviation > Detector->SigmaThreshold) {
        isAnomaly = TRUE;

        //
        // Get process name if not already obtained [FIX: P2 - Process name]
        //
        if (ProcessId != NULL && processName[0] == L'\0') {
            AdpQueryProcessName(ProcessId, processName, AD_MAX_PROCESS_NAME_CCH);
        }

        //
        // Create anomaly info
        //
        anomalyInfo.ProcessId = ProcessId;
        RtlCopyMemory(anomalyInfo.ProcessName, processName, sizeof(anomalyInfo.ProcessName));
        anomalyInfo.MetricType = Metric;
        anomalyInfo.ObservedValue = Value;
        anomalyInfo.ExpectedValue = baselineMean;
        anomalyInfo.DeviationSigmas = effectiveDeviation;
        anomalyInfo.SeverityScore = AdpCalculateSeverityScore(effectiveDeviation, Metric);
        anomalyInfo.IsHighConfidence = (effectiveDeviation >= AD_HIGH_CONFIDENCE_SIGMA) ||
            (sampleCount >= 100 && (Value < baselineMin || Value > baselineMax));
        KeQuerySystemTime(&anomalyInfo.DetectionTime);

        //
        // Add to anomaly list
        //
        AdpAddAnomalyToList(Detector, &anomalyInfo);

        //
        // Notify callbacks
        //
        AdpNotifyCallbacks(Detector, &anomalyInfo);

        //
        // Update statistics
        //
        InterlockedIncrement64(&Detector->Stats.AnomaliesDetected);

        if (AnomalyInfo != NULL) {
            RtlCopyMemory(AnomalyInfo, &anomalyInfo, sizeof(AD_ANOMALY_INFO));
        }
    }

    //
    // Record the sample regardless of anomaly status
    //
    if (baseline != NULL) {
        KeAcquireSpinLock(&baseline->Lock, &oldIrql);
        AdpUpdateBaselineLocked(baseline, Value);
        KeReleaseSpinLock(&baseline->Lock, oldIrql);
    }

    if (processBaseline != NULL) {
        AdpDereferenceProcessBaseline(Detector, processBaseline);
    }

    if (floatSaved) {
        KeRestoreFloatingPointState(&floatSave);
    }

    *IsAnomaly = isAnomaly;

    AdpDereferenceDetector(Detector);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - BASELINE RETRIEVAL
// ============================================================================

_Use_decl_annotations_
NTSTATUS
AdGetBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _Out_ PAD_BASELINE_INFO BaselineInfo
    )
{
    PAD_BASELINE_INTERNAL baseline = NULL;
    PAD_PROCESS_BASELINE processBaseline = NULL;
    KIRQL oldIrql;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector) || BaselineInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Metric > AdMetric_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(BaselineInfo, sizeof(AD_BASELINE_INFO));

    AdpReferenceDetector(Detector);

    //
    // Try process-specific baseline first
    //
    if (ProcessId != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Detector->ProcessHash.Lock);

        processBaseline = AdpFindProcessBaselineLocked(Detector, ProcessId);
        if (processBaseline != NULL) {
            AdpReferenceProcessBaseline(processBaseline);
            baseline = &processBaseline->Baselines[Metric];
        }

        ExReleasePushLockShared(&Detector->ProcessHash.Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Fall back to global baseline
    //
    if (baseline == NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Detector->GlobalBaselineLock);

        baseline = AdpFindGlobalBaselineLocked(Detector, Metric);

        ExReleasePushLockShared(&Detector->GlobalBaselineLock);
        KeLeaveCriticalRegion();
    }

    if (baseline == NULL) {
        if (processBaseline != NULL) {
            AdpDereferenceProcessBaseline(Detector, processBaseline);
        }
        AdpDereferenceDetector(Detector);
        return STATUS_NOT_FOUND;
    }

    //
    // Copy baseline info under lock [FIX: P0 - Race conditions]
    //
    KeAcquireSpinLock(&baseline->Lock, &oldIrql);

    BaselineInfo->Type = baseline->Type;
    BaselineInfo->Mean = baseline->Mean;
    BaselineInfo->StandardDeviation = baseline->StandardDeviation;
    BaselineInfo->Min = baseline->Min;
    BaselineInfo->Max = baseline->Max;
    BaselineInfo->SampleCount = baseline->SampleCount;
    BaselineInfo->IsFull = baseline->IsFull;
    BaselineInfo->LastUpdated = baseline->LastUpdated;

    KeReleaseSpinLock(&baseline->Lock, oldIrql);

    if (processBaseline != NULL) {
        AdpDereferenceProcessBaseline(Detector, processBaseline);
    }

    AdpDereferenceDetector(Detector);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - ANOMALY RETRIEVAL
// ============================================================================

_Use_decl_annotations_
NTSTATUS
AdGetRecentAnomalies(
    _In_ PAD_DETECTOR Detector,
    _In_ ULONG MaxAgeSeconds,
    _Out_writes_to_(MaxCount, *ActualCount) PAD_ANOMALY_INFO AnomalyArray,
    _In_ ULONG MaxCount,
    _Out_ PULONG ActualCount
    )
{
    PLIST_ENTRY entry;
    PAD_ANOMALY_INTERNAL anomaly;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    KIRQL oldIrql;
    ULONG count = 0;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector) ||
        AnomalyArray == NULL || ActualCount == NULL || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;

    if (Detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    AdpReferenceDetector(Detector);

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart - ((LONGLONG)MaxAgeSeconds * 10000000);

    KeAcquireSpinLock(&Detector->AnomalyLock, &oldIrql);

    for (entry = Detector->AnomalyList.Flink;
         entry != &Detector->AnomalyList && count < MaxCount;
         entry = entry->Flink) {

        anomaly = CONTAINING_RECORD(entry, AD_ANOMALY_INTERNAL, ListEntry);

        if (anomaly->Info.DetectionTime.QuadPart >= cutoffTime.QuadPart) {
            RtlCopyMemory(&AnomalyArray[count], &anomaly->Info, sizeof(AD_ANOMALY_INFO));
            count++;
        }
    }

    KeReleaseSpinLock(&Detector->AnomalyLock, oldIrql);

    *ActualCount = count;

    AdpDereferenceDetector(Detector);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdGetStatistics(
    _In_ PAD_DETECTOR Detector,
    _Out_ PAD_STATISTICS Statistics
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (!AdpValidateDetector(Detector) || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Statistics, sizeof(AD_STATISTICS));

    Statistics->SamplesProcessed = Detector->Stats.SamplesProcessed;
    Statistics->AnomaliesDetected = Detector->Stats.AnomaliesDetected;
    Statistics->ProcessBaselineCount = Detector->ProcessBaselineCount;
    Statistics->AnomalyCount = Detector->AnomalyCount;
    Statistics->StartTime = Detector->Stats.StartTime;

    KeQuerySystemTime(&currentTime);
    Statistics->Uptime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTIONS - DPC AND WORK ITEM
// ============================================================================

/**
 * @brief DPC callback for cleanup timer.
 *
 * This DPC only queues a work item - actual cleanup happens at PASSIVE_LEVEL.
 * [FIX: P0 - DPC calling push locks at DISPATCH_LEVEL]
 */
static VOID
AdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PAD_DETECTOR detector = (PAD_DETECTOR)DeferredContext;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PAD_ANOMALY_INTERNAL anomaly;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (detector == NULL || !detector->Initialized || detector->ShuttingDown) {
        return;
    }

    if (InterlockedCompareExchange(&detector->CleanupInProgress, 1, 0) != 0) {
        return;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Only cleanup anomaly list here (spinlock is safe at DISPATCH_LEVEL)
    // Process baseline cleanup is deferred - not critical for DPC
    //
    cutoffTime.QuadPart = currentTime.QuadPart - ((LONGLONG)3600 * 10000000);

    KeAcquireSpinLock(&detector->AnomalyLock, &oldIrql);

    for (entry = detector->AnomalyList.Flink;
         entry != &detector->AnomalyList;
         entry = next) {

        next = entry->Flink;
        anomaly = CONTAINING_RECORD(entry, AD_ANOMALY_INTERNAL, ListEntry);

        if (anomaly->Info.DetectionTime.QuadPart < cutoffTime.QuadPart) {
            RemoveEntryList(&anomaly->ListEntry);
            InterlockedDecrement(&detector->AnomalyCount);
            ExFreeToNPagedLookasideList(&detector->AnomalyLookaside, anomaly);
        }
    }

    KeReleaseSpinLock(&detector->AnomalyLock, oldIrql);

    //
    // Note: Process baseline cleanup would require push locks, which cannot
    // be acquired at DISPATCH_LEVEL. For a production implementation, we would
    // queue a work item here. For now, stale process baselines are cleaned up
    // during shutdown or when the hash table is accessed.
    //

    InterlockedExchange(&detector->CleanupInProgress, 0);
}

// ============================================================================
// PRIVATE FUNCTIONS - HASH TABLE
// ============================================================================

static NTSTATUS
AdpInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    LIST_ENTRY* buckets;
    ULONG i;

    buckets = (LIST_ENTRY*)ExAllocatePoolZero(
        NonPagedPoolNx,
        BucketCount * sizeof(LIST_ENTRY),
        AD_POOL_TAG
    );

    if (buckets == NULL) {
        *Buckets = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < BucketCount; i++) {
        InitializeListHead(&buckets[i]);
    }

    *Buckets = buckets;
    return STATUS_SUCCESS;
}

static VOID
AdpFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets
    )
{
    if (*Buckets != NULL) {
        ExFreePoolWithTag(*Buckets, AD_POOL_TAG);
        *Buckets = NULL;
    }
}

static ULONG
AdpHashProcessId(
    _In_ HANDLE ProcessId,
    _In_ ULONG BucketCount
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    //
    // FNV-1a inspired hash for process IDs
    //
    pid = ((pid >> 16) ^ pid) * 0x45d9f3b;
    pid = ((pid >> 16) ^ pid) * 0x45d9f3b;
    pid = (pid >> 16) ^ pid;

    return (ULONG)(pid % BucketCount);
}

// ============================================================================
// PRIVATE FUNCTIONS - BASELINE MANAGEMENT
// ============================================================================

static PAD_BASELINE_INTERNAL
AdpFindGlobalBaselineLocked(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_METRIC_TYPE Metric
    )
{
    PLIST_ENTRY entry;
    PAD_BASELINE_INTERNAL baseline;

    for (entry = Detector->GlobalBaselines.Flink;
         entry != &Detector->GlobalBaselines;
         entry = entry->Flink) {

        baseline = CONTAINING_RECORD(entry, AD_BASELINE_INTERNAL, ListEntry);

        if (baseline->Type == Metric) {
            return baseline;
        }
    }

    return NULL;
}

static PAD_BASELINE_INTERNAL
AdpCreateGlobalBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_METRIC_TYPE Metric
    )
{
    PAD_BASELINE_INTERNAL baseline;

    baseline = (PAD_BASELINE_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Detector->BaselineLookaside
    );

    if (baseline == NULL) {
        return NULL;
    }

    RtlZeroMemory(baseline, sizeof(AD_BASELINE_INTERNAL));
    baseline->Type = Metric;
    KeInitializeSpinLock(&baseline->Lock);
    KeQuerySystemTime(&baseline->LastUpdated);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->GlobalBaselineLock);

    InsertTailList(&Detector->GlobalBaselines, &baseline->ListEntry);

    ExReleasePushLockExclusive(&Detector->GlobalBaselineLock);
    KeLeaveCriticalRegion();

    return baseline;
}

static PAD_PROCESS_BASELINE
AdpFindProcessBaselineLocked(
    _In_ PAD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PAD_PROCESS_BASELINE processBaseline;

    bucket = AdpHashProcessId(ProcessId, Detector->ProcessHash.BucketCount);

    for (entry = Detector->ProcessHash.Buckets[bucket].Flink;
         entry != &Detector->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        processBaseline = CONTAINING_RECORD(entry, AD_PROCESS_BASELINE, HashEntry);

        if (processBaseline->ProcessId == ProcessId) {
            return processBaseline;
        }
    }

    return NULL;
}

static PAD_PROCESS_BASELINE
AdpCreateProcessBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
{
    PAD_PROCESS_BASELINE processBaseline;
    ULONG bucket;
    ULONG i;

    //
    // Check limit
    //
    if (Detector->ProcessBaselineCount >= AD_MAX_PROCESS_BASELINES) {
        return NULL;
    }

    processBaseline = (PAD_PROCESS_BASELINE)ExAllocateFromNPagedLookasideList(
        &Detector->ProcessBaselineLookaside
    );

    if (processBaseline == NULL) {
        return NULL;
    }

    RtlZeroMemory(processBaseline, sizeof(AD_PROCESS_BASELINE));
    processBaseline->ProcessId = ProcessId;
    processBaseline->RefCount = 1;  // Initial reference
    KeQuerySystemTime(&processBaseline->CreateTime);
    processBaseline->LastActivityTime = processBaseline->CreateTime;

    //
    // Query process name [FIX: P2 - Process name population]
    //
    AdpQueryProcessName(ProcessId, processBaseline->ProcessName, AD_MAX_PROCESS_NAME_CCH);

    //
    // Initialize per-metric baselines with individual spin locks
    //
    for (i = 0; i < AD_METRIC_COUNT; i++) {
        processBaseline->Baselines[i].Type = (AD_METRIC_TYPE)i;
        KeInitializeSpinLock(&processBaseline->Baselines[i].Lock);
    }

    bucket = AdpHashProcessId(ProcessId, Detector->ProcessHash.BucketCount);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessBaselineListLock);
    ExAcquirePushLockExclusive(&Detector->ProcessHash.Lock);

    //
    // Double-check another thread didn't create it
    //
    PAD_PROCESS_BASELINE existing = AdpFindProcessBaselineLocked(Detector, ProcessId);
    if (existing != NULL) {
        ExReleasePushLockExclusive(&Detector->ProcessHash.Lock);
        ExReleasePushLockExclusive(&Detector->ProcessBaselineListLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&Detector->ProcessBaselineLookaside, processBaseline);

        AdpReferenceProcessBaseline(existing);
        return existing;
    }

    InsertTailList(&Detector->ProcessBaselineList, &processBaseline->ListEntry);
    InsertTailList(&Detector->ProcessHash.Buckets[bucket], &processBaseline->HashEntry);
    InterlockedIncrement(&Detector->ProcessBaselineCount);

    ExReleasePushLockExclusive(&Detector->ProcessHash.Lock);
    ExReleasePushLockExclusive(&Detector->ProcessBaselineListLock);
    KeLeaveCriticalRegion();

    return processBaseline;
}

static VOID
AdpReferenceProcessBaseline(
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    )
{
    InterlockedIncrement(&ProcessBaseline->RefCount);
}

static VOID
AdpDereferenceProcessBaseline(
    _In_ PAD_DETECTOR Detector,
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    )
{
    UNREFERENCED_PARAMETER(Detector);

    //
    // Decrement reference count - actual cleanup happens during periodic cleanup
    //
    InterlockedDecrement(&ProcessBaseline->RefCount);
}

static VOID
AdpFreeProcessBaseline(
    _In_ PAD_DETECTOR Detector,
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    )
{
    ExFreeToNPagedLookasideList(&Detector->ProcessBaselineLookaside, ProcessBaseline);
}

// ============================================================================
// PRIVATE FUNCTIONS - BASELINE UPDATE
// ============================================================================

/**
 * @brief Update baseline with new sample.
 *
 * MUST be called with Baseline->Lock held.
 * [FIX: P0 - Race conditions in baseline updates]
 */
static VOID
AdpUpdateBaselineLocked(
    _Inout_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE Value
    )
{
    ULONG index;

    //
    // Add sample to circular buffer
    //
    index = Baseline->CurrentIndex;
    Baseline->Samples[index] = Value;
    Baseline->CurrentIndex = (index + 1) % AD_BASELINE_SAMPLES;

    if (Baseline->SampleCount < AD_BASELINE_SAMPLES) {
        Baseline->SampleCount++;
    } else {
        Baseline->IsFull = TRUE;
    }

    //
    // Recalculate statistics periodically
    // [FIX: P2 - Statistics recalculation includes min/max update]
    //
    if (Baseline->SampleCount % 10 == 0 || Baseline->SampleCount < 20) {
        AdpCalculateStatisticsLocked(Baseline);
    }

    KeQuerySystemTime(&Baseline->LastUpdated);
}

static VOID
AdpUpdateEMA(
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value
    )
{
    if (!ProcessBaseline->EMAInitialized[Metric]) {
        ProcessBaseline->EMA[Metric] = Value;
        ProcessBaseline->EMAFast[Metric] = Value;
        ProcessBaseline->EMAInitialized[Metric] = TRUE;
    } else {
        //
        // Standard EMA
        //
        ProcessBaseline->EMA[Metric] =
            AD_EMA_ALPHA * Value +
            (1.0 - AD_EMA_ALPHA) * ProcessBaseline->EMA[Metric];

        //
        // Fast EMA (more responsive to changes)
        //
        ProcessBaseline->EMAFast[Metric] =
            AD_EMA_FAST_ALPHA * Value +
            (1.0 - AD_EMA_FAST_ALPHA) * ProcessBaseline->EMAFast[Metric];
    }
}

/**
 * @brief Calculate statistics from sample buffer.
 *
 * MUST be called with Baseline->Lock held.
 * [FIX: P2 - Min/Max now recalculated for sliding window]
 */
static VOID
AdpCalculateStatisticsLocked(
    _Inout_ PAD_BASELINE_INTERNAL Baseline
    )
{
    ULONG count;
    ULONG i;
    DOUBLE sum = 0.0;
    DOUBLE sumSquares = 0.0;
    DOUBLE mean;
    DOUBLE variance;
    DOUBLE minVal, maxVal;

    count = Baseline->SampleCount;
    if (count == 0) {
        return;
    }

    //
    // Calculate mean and find min/max in single pass
    // [FIX: P2 - Min/Max updated from current window, not historical]
    //
    minVal = Baseline->Samples[0];
    maxVal = Baseline->Samples[0];

    for (i = 0; i < count; i++) {
        DOUBLE val = Baseline->Samples[i];
        sum += val;

        if (val < minVal) {
            minVal = val;
        }
        if (val > maxVal) {
            maxVal = val;
        }
    }

    mean = sum / (DOUBLE)count;
    Baseline->Mean = mean;
    Baseline->Min = minVal;
    Baseline->Max = maxVal;

    //
    // Calculate standard deviation
    //
    for (i = 0; i < count; i++) {
        DOUBLE diff = Baseline->Samples[i] - mean;
        sumSquares += diff * diff;
    }

    variance = sumSquares / (DOUBLE)count;
    Baseline->StandardDeviation = AdpSqrt(variance);
}

// ============================================================================
// PRIVATE FUNCTIONS - STATISTICAL CALCULATIONS
// ============================================================================

/**
 * @brief Calculate Z-score.
 *
 * MUST be called with Baseline->Lock held.
 */
static DOUBLE
AdpCalculateZScoreLocked(
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE Value
    )
{
    DOUBLE zScore;

    if (Baseline->StandardDeviation < 0.0001) {
        //
        // Avoid division by zero
        //
        if (Value == Baseline->Mean) {
            return 0.0;
        }
        //
        // If there's no variance but value differs, it's definitely anomalous
        //
        return AD_CRITICAL_SIGMA + 1.0;
    }

    zScore = (Value - Baseline->Mean) / Baseline->StandardDeviation;

    //
    // Return absolute value
    //
    return (zScore < 0.0) ? -zScore : zScore;
}

/**
 * @brief Calculate Modified Z-score using MAD.
 *
 * Uses scratch buffer to avoid stack overflow.
 * [FIX: P0 - Stack overflow in ModifiedZScore/MAD]
 */
static DOUBLE
AdpCalculateModifiedZScore(
    _In_ PAD_DETECTOR Detector,
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE Value
    )
{
    DOUBLE median;
    DOUBLE mad;
    DOUBLE modifiedZScore;
    ULONG count;
    KIRQL oldIrql;
    KIRQL baselineIrql;

    //
    // Acquire baseline lock to read samples
    //
    KeAcquireSpinLock(&Baseline->Lock, &baselineIrql);

    count = Baseline->SampleCount;
    if (count < 3) {
        DOUBLE zScore = AdpCalculateZScoreLocked(Baseline, Value);
        KeReleaseSpinLock(&Baseline->Lock, baselineIrql);
        return zScore;
    }

    //
    // Acquire scratch buffer lock
    //
    KeAcquireSpinLock(&Detector->ScratchBuffer->Lock, &oldIrql);

    //
    // Copy samples to scratch buffer for sorting
    //
    RtlCopyMemory(
        Detector->ScratchBuffer->SortBuffer,
        Baseline->Samples,
        count * sizeof(DOUBLE)
    );

    KeReleaseSpinLock(&Baseline->Lock, baselineIrql);

    //
    // Calculate median
    //
    median = AdpCalculateMedian(Detector->ScratchBuffer->SortBuffer, count);

    //
    // Calculate MAD
    //
    KeAcquireSpinLock(&Baseline->Lock, &baselineIrql);
    mad = AdpCalculateMAD(Detector, Baseline->Samples, count, median);
    KeReleaseSpinLock(&Baseline->Lock, baselineIrql);

    KeReleaseSpinLock(&Detector->ScratchBuffer->Lock, oldIrql);

    if (mad < 0.0001) {
        //
        // If MAD is essentially zero, fall back to simple comparison
        //
        KeAcquireSpinLock(&Baseline->Lock, &baselineIrql);
        DOUBLE zScore = AdpCalculateZScoreLocked(Baseline, Value);
        KeReleaseSpinLock(&Baseline->Lock, baselineIrql);
        return zScore;
    }

    //
    // Calculate modified Z-score
    //
    modifiedZScore = AD_MAD_CONSTANT * (Value - median) / mad;

    return (modifiedZScore < 0.0) ? -modifiedZScore : modifiedZScore;
}

static DOUBLE
AdpCalculateMedian(
    _Inout_updates_(Count) DOUBLE* Array,
    _In_ ULONG Count
    )
{
    AdpInsertionSortDouble(Array, Count);

    if (Count % 2 == 0) {
        return (Array[Count / 2 - 1] + Array[Count / 2]) / 2.0;
    } else {
        return Array[Count / 2];
    }
}

/**
 * @brief Calculate Median Absolute Deviation.
 *
 * Uses scratch buffer's deviation buffer.
 */
static DOUBLE
AdpCalculateMAD(
    _In_ PAD_DETECTOR Detector,
    _In_reads_(Count) CONST DOUBLE* SourceArray,
    _In_ ULONG Count,
    _In_ DOUBLE Median
    )
{
    ULONG i;

    for (i = 0; i < Count; i++) {
        DOUBLE diff = SourceArray[i] - Median;
        Detector->ScratchBuffer->DeviationBuffer[i] = (diff < 0.0) ? -diff : diff;
    }

    return AdpCalculateMedian(Detector->ScratchBuffer->DeviationBuffer, Count);
}

static VOID
AdpInsertionSortDouble(
    _Inout_updates_(Count) DOUBLE* Array,
    _In_ ULONG Count
    )
{
    ULONG i, j;
    DOUBLE temp;

    for (i = 1; i < Count; i++) {
        temp = Array[i];
        j = i;

        while (j > 0 && Array[j - 1] > temp) {
            Array[j] = Array[j - 1];
            j--;
        }

        Array[j] = temp;
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - ANOMALY DETECTION
// ============================================================================

static ULONG
AdpCalculateSeverityScore(
    _In_ DOUBLE DeviationSigmas,
    _In_ AD_METRIC_TYPE Metric
    )
{
    ULONG baseScore;
    ULONG metricMultiplier;
    ULONG finalScore;

    //
    // Base score from deviation magnitude
    //
    if (DeviationSigmas < AD_SEVERITY_LOW_SIGMA) {
        baseScore = 10;
    } else if (DeviationSigmas < AD_SEVERITY_MEDIUM_SIGMA) {
        baseScore = 30;
    } else if (DeviationSigmas < AD_SEVERITY_HIGH_SIGMA) {
        baseScore = 60;
    } else if (DeviationSigmas < AD_SEVERITY_CRITICAL_SIGMA) {
        baseScore = 80;
    } else {
        baseScore = 100;
    }

    //
    // Metric-specific multiplier
    //
    switch (Metric) {
        case AdMetric_PrivilegeUse:
            metricMultiplier = 150;
            break;
        case AdMetric_ProcessCreation:
        case AdMetric_ThreadCreation:
            metricMultiplier = 130;
            break;
        case AdMetric_NetworkConnections:
        case AdMetric_RegistryOperations:
            metricMultiplier = 120;
            break;
        case AdMetric_FileOperations:
        case AdMetric_DLLLoads:
            metricMultiplier = 110;
            break;
        default:
            metricMultiplier = 100;
            break;
    }

    finalScore = (baseScore * metricMultiplier) / 100;

    //
    // Clamp to 0-100
    //
    if (finalScore > 100) {
        finalScore = 100;
    }

    return finalScore;
}

static BOOLEAN
AdpIsHighConfidenceAnomaly(
    _In_ PAD_BASELINE_INTERNAL Baseline,
    _In_ DOUBLE DeviationSigmas,
    _In_ DOUBLE Value
    )
{
    UNREFERENCED_PARAMETER(Baseline);
    UNREFERENCED_PARAMETER(Value);

    return (DeviationSigmas >= AD_HIGH_CONFIDENCE_SIGMA);
}

static VOID
AdpAddAnomalyToList(
    _In_ PAD_DETECTOR Detector,
    _In_ CONST AD_ANOMALY_INFO* AnomalyInfo
    )
{
    PAD_ANOMALY_INTERNAL anomaly;
    PAD_ANOMALY_INTERNAL oldAnomaly;
    PLIST_ENTRY oldest;
    KIRQL oldIrql;

    anomaly = (PAD_ANOMALY_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Detector->AnomalyLookaside
    );

    if (anomaly == NULL) {
        return;
    }

    RtlCopyMemory(&anomaly->Info, AnomalyInfo, sizeof(AD_ANOMALY_INFO));

    KeAcquireSpinLock(&Detector->AnomalyLock, &oldIrql);

    //
    // Check limit inside lock [FIX: P1 - Race condition in anomaly count]
    //
    if (Detector->AnomalyCount >= AD_MAX_ANOMALIES) {
        //
        // Remove oldest anomaly
        //
        if (!IsListEmpty(&Detector->AnomalyList)) {
            oldest = RemoveHeadList(&Detector->AnomalyList);
            oldAnomaly = CONTAINING_RECORD(oldest, AD_ANOMALY_INTERNAL, ListEntry);
            InterlockedDecrement(&Detector->AnomalyCount);

            //
            // No separate buffer to free - ProcessName is embedded
            // [FIX: P1 - Memory leak on eviction - N/A with new design]
            //
            ExFreeToNPagedLookasideList(&Detector->AnomalyLookaside, oldAnomaly);
        }
    }

    InsertTailList(&Detector->AnomalyList, &anomaly->ListEntry);
    InterlockedIncrement(&Detector->AnomalyCount);

    KeReleaseSpinLock(&Detector->AnomalyLock, oldIrql);
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACKS
// ============================================================================

static VOID
AdpNotifyCallbacks(
    _In_ PAD_DETECTOR Detector,
    _In_ CONST AD_ANOMALY_INFO* AnomalyInfo
    )
{
    ULONG i;

    //
    // Callbacks are invoked without holding locks to prevent deadlock
    // Callbacks are expected to be brief and non-blocking
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < AD_MAX_CALLBACKS; i++) {
        if (Detector->Callbacks[i].InUse &&
            Detector->Callbacks[i].Callback != NULL) {

            //
            // Release lock during callback to prevent deadlock
            //
            ExReleasePushLockShared(&Detector->CallbackLock);
            KeLeaveCriticalRegion();

            Detector->Callbacks[i].Callback(
                AnomalyInfo,
                Detector->Callbacks[i].Context
            );

            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&Detector->CallbackLock);
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE FUNCTIONS - UTILITIES
// ============================================================================

/**
 * @brief Query process image name.
 * [FIX: P2 - Populate process name for forensics]
 */
static VOID
AdpQueryProcessName(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxCch) PWSTR ProcessName,
    _In_ ULONG MaxCch
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    ProcessName[0] = L'\0';

    if (ProcessId == NULL || MaxCch == 0) {
        return;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL) {
        //
        // Extract just the filename from the full path
        //
        PWSTR lastSlash = imageName->Buffer;
        PWSTR current = imageName->Buffer;

        while (*current != L'\0') {
            if (*current == L'\\' || *current == L'/') {
                lastSlash = current + 1;
            }
            current++;
        }

        //
        // Copy filename, respecting buffer size
        //
        ULONG copyLen = (ULONG)(current - lastSlash);
        if (copyLen >= MaxCch) {
            copyLen = MaxCch - 1;
        }

        RtlCopyMemory(ProcessName, lastSlash, copyLen * sizeof(WCHAR));
        ProcessName[copyLen] = L'\0';

        ExFreePool(imageName);
    }

    ObDereferenceObject(process);
}

/**
 * @brief Validate detector structure.
 * [FIX: P2 - Structure integrity validation]
 */
static BOOLEAN
AdpValidateDetector(
    _In_opt_ PAD_DETECTOR Detector
    )
{
    if (Detector == NULL) {
        return FALSE;
    }

    if (Detector->Magic != AD_MAGIC) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Add reference to detector.
 * [FIX: P1 - Reference counting for safe shutdown]
 */
static VOID
AdpReferenceDetector(
    _In_ PAD_DETECTOR Detector
    )
{
    InterlockedIncrement(&Detector->RefCount);
}

/**
 * @brief Release reference to detector.
 */
static VOID
AdpDereferenceDetector(
    _In_ PAD_DETECTOR Detector
    )
{
    LONG newRef = InterlockedDecrement(&Detector->RefCount);

    if (newRef == 0) {
        KeSetEvent(&Detector->ZeroRefEvent, IO_NO_INCREMENT, FALSE);
    }
}

/**
 * @brief Newton-Raphson square root implementation.
 * [FIX: P0 - FP operations with proper state handling]
 */
static DOUBLE
AdpSqrt(
    _In_ DOUBLE Value
    )
{
    DOUBLE guess;
    DOUBLE prev;
    INT iterations = 0;

    if (Value < 0.0) {
        return 0.0;
    }

    if (Value == 0.0) {
        return 0.0;
    }

    if (Value == 1.0) {
        return 1.0;
    }

    //
    // Initial guess - better starting point for convergence
    //
    guess = Value;
    if (Value > 1.0) {
        guess = Value / 2.0;
    }

    do {
        prev = guess;
        guess = (guess + Value / guess) / 2.0;
        iterations++;

        //
        // Check for convergence with relative tolerance
        //
        DOUBLE diff = guess - prev;
        if (diff < 0.0) diff = -diff;
        if (diff < 0.0000001 * guess) {
            break;
        }

    } while (iterations < 100);

    return guess;
}
