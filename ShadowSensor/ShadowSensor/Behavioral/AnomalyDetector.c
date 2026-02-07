/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ANOMALY DETECTION ENGINE
 * ============================================================================
 *
 * @file AnomalyDetector.c
 * @brief Enterprise-grade statistical anomaly detection for behavioral analysis.
 *
 * This module implements comprehensive anomaly detection capabilities:
 * - Statistical baseline establishment per process and globally
 * - Z-score based anomaly detection (configurable sigma threshold)
 * - Sliding window sample collection for adaptive baselines
 * - Multi-metric monitoring (CPU, memory, file ops, network, etc.)
 * - Process-specific behavioral profiling
 * - Exponential moving average for trend detection
 * - Seasonal pattern recognition
 * - Outlier detection using modified Z-score (MAD-based)
 *
 * Detection Capabilities (MITRE ATT&CK):
 * - T1059: Command and Scripting Interpreter (unusual execution patterns)
 * - T1055: Process Injection (abnormal memory operations)
 * - T1071: Application Layer Protocol (network anomalies)
 * - T1486: Data Encrypted for Impact (file operation anomalies)
 * - T1003: OS Credential Dumping (LSASS access anomalies)
 * - T1562: Impair Defenses (registry operation anomalies)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AnomalyDetector.h"
#include "BehaviorEngine.h"
#include "ThreatScoring.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, AdInitialize)
#pragma alloc_text(PAGE, AdShutdown)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define AD_VERSION                          0x0200
#define AD_MAX_PROCESS_BASELINES            4096
#define AD_MAX_GLOBAL_BASELINES             64
#define AD_MAX_ANOMALIES                    10000
#define AD_MAX_CALLBACKS                    8
#define AD_CLEANUP_INTERVAL_MS              60000
#define AD_BASELINE_UPDATE_INTERVAL_MS      1000
#define AD_MIN_SAMPLES_FOR_DETECTION        10
#define AD_STALE_BASELINE_AGE_MS            3600000     // 1 hour

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
 * @brief Per-process baseline context.
 */
typedef struct _AD_PROCESS_BASELINE {
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastActivityTime;

    //
    // Per-metric baselines
    //
    AD_BASELINE Baselines[AdMetric_Custom + 1];
    ULONG BaselineCount;

    //
    // Exponential moving averages
    //
    DOUBLE EMA[AdMetric_Custom + 1];
    DOUBLE EMAFast[AdMetric_Custom + 1];
    BOOLEAN EMAInitialized[AdMetric_Custom + 1];

    //
    // Reference counting
    //
    volatile LONG RefCount;

    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

} AD_PROCESS_BASELINE, *PAD_PROCESS_BASELINE;

/**
 * @brief Internal detector state.
 */
typedef struct _AD_DETECTOR_INTERNAL {
    AD_DETECTOR Public;

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
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST BaselineLookaside;
    NPAGED_LOOKASIDE_LIST AnomalyLookaside;
    NPAGED_LOOKASIDE_LIST ProcessBaselineLookaside;
    BOOLEAN LookasideInitialized;
    UINT8 Reserved1[7];

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile LONG CleanupInProgress;

    //
    // Additional callbacks
    //
    struct {
        AD_ANOMALY_CALLBACK Callback;
        PVOID Context;
        BOOLEAN InUse;
        UINT8 Reserved[7];
    } AdditionalCallbacks[AD_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

} AD_DETECTOR_INTERNAL, *PAD_DETECTOR_INTERNAL;

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

static NTSTATUS
AdpInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static VOID
AdpFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static ULONG
AdpHashProcessId(
    _In_ HANDLE ProcessId
    );

static PAD_BASELINE
AdpFindGlobalBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_METRIC_TYPE Metric
    );

static PAD_BASELINE
AdpCreateGlobalBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ AD_METRIC_TYPE Metric
    );

static PAD_PROCESS_BASELINE
AdpFindProcessBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    );

static PAD_PROCESS_BASELINE
AdpCreateProcessBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    );

static VOID
AdpFreeProcessBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    );

static VOID
AdpUpdateBaseline(
    _Inout_ PAD_BASELINE Baseline,
    _In_ DOUBLE Value
    );

static VOID
AdpUpdateEMA(
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value
    );

static VOID
AdpCalculateStatistics(
    _Inout_ PAD_BASELINE Baseline
    );

static DOUBLE
AdpCalculateZScore(
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE Value
    );

static DOUBLE
AdpCalculateModifiedZScore(
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE Value
    );

static ULONG
AdpCalculateSeverityScore(
    _In_ DOUBLE DeviationSigmas,
    _In_ AD_METRIC_TYPE Metric
    );

static BOOLEAN
AdpIsHighConfidenceAnomaly(
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE DeviationSigmas,
    _In_ DOUBLE Value
    );

static PAD_ANOMALY
AdpCreateAnomaly(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE ObservedValue,
    _In_ DOUBLE DeviationSigmas
    );

static VOID
AdpNotifyCallbacks(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ PAD_ANOMALY Anomaly
    );

static VOID
AdpAddAnomalyToList(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ PAD_ANOMALY Anomaly
    );

static DOUBLE
AdpCalculateMedian(
    _In_ DOUBLE* Array,
    _In_ ULONG Count
    );

static DOUBLE
AdpCalculateMAD(
    _In_ DOUBLE* Array,
    _In_ ULONG Count,
    _In_ DOUBLE Median
    );

static VOID
AdpQuickSortDouble(
    _Inout_ DOUBLE* Array,
    _In_ ULONG Count
    );

static const CHAR*
AdpMetricTypeToString(
    _In_ AD_METRIC_TYPE Metric
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
    PAD_DETECTOR_INTERNAL detector = NULL;
    LARGE_INTEGER timerDue;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    detector = (PAD_DETECTOR_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(AD_DETECTOR_INTERNAL),
        AD_POOL_TAG
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detector, sizeof(AD_DETECTOR_INTERNAL));

    //
    // Initialize lists and locks
    //
    InitializeListHead(&detector->Public.GlobalBaselines);
    ExInitializePushLock(&detector->Public.GlobalBaselineLock);

    InitializeListHead(&detector->Public.ProcessBaselines);
    ExInitializePushLock(&detector->Public.ProcessBaselineLock);

    InitializeListHead(&detector->Public.AnomalyList);
    KeInitializeSpinLock(&detector->Public.AnomalyLock);

    InitializeListHead(&detector->ProcessBaselineList);
    ExInitializePushLock(&detector->ProcessBaselineListLock);

    ExInitializePushLock(&detector->CallbackLock);

    //
    // Initialize process hash table
    //
    status = AdpInitializeHashTable(
        &detector->ProcessHash.Buckets,
        1024
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(detector, AD_POOL_TAG);
        return status;
    }

    detector->ProcessHash.BucketCount = 1024;
    ExInitializePushLock(&detector->ProcessHash.Lock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &detector->BaselineLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AD_BASELINE),
        AD_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &detector->AnomalyLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AD_ANOMALY),
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
    // Initialize default configuration
    //
    detector->Public.SigmaThreshold = AD_DEFAULT_SIGMA_THRESHOLD;
    detector->Public.MinimumSamples = AD_MIN_SAMPLES_FOR_DETECTION;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&detector->CleanupTimer);
    KeInitializeDpc(
        &detector->CleanupDpc,
        AdpCleanupTimerDpc,
        detector
    );

    timerDue.QuadPart = -((LONGLONG)AD_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &detector->CleanupTimer,
        timerDue,
        AD_CLEANUP_INTERVAL_MS,
        &detector->CleanupDpc
    );

    //
    // Initialize global baselines for each metric type
    //
    for (i = 0; i <= AdMetric_Custom; i++) {
        AdpCreateGlobalBaseline(detector, (AD_METRIC_TYPE)i);
    }

    //
    // Record start time
    //
    KeQuerySystemTime(&detector->Public.Stats.StartTime);

    detector->Public.Initialized = TRUE;
    *Detector = &detector->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
AdShutdown(
    _Inout_ PAD_DETECTOR Detector
    )
{
    PAD_DETECTOR_INTERNAL detector;
    PLIST_ENTRY entry;
    PAD_BASELINE baseline;
    PAD_ANOMALY anomaly;
    PAD_PROCESS_BASELINE processBaseline;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, AD_DETECTOR_INTERNAL, Public);

    //
    // Mark as shutting down
    //
    Detector->Initialized = FALSE;

    //
    // Cancel the cleanup timer
    //
    KeCancelTimer(&detector->CleanupTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for cleanup to complete
    //
    while (detector->CleanupInProgress) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all global baselines
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->GlobalBaselineLock);

    while (!IsListEmpty(&Detector->GlobalBaselines)) {
        entry = RemoveHeadList(&Detector->GlobalBaselines);
        baseline = CONTAINING_RECORD(entry, AD_BASELINE, ListEntry);
        ExFreeToNPagedLookasideList(&detector->BaselineLookaside, baseline);
    }

    ExReleasePushLockExclusive(&Detector->GlobalBaselineLock);
    KeLeaveCriticalRegion();

    //
    // Free all process baselines
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->ProcessBaselineListLock);

    while (!IsListEmpty(&detector->ProcessBaselineList)) {
        entry = RemoveHeadList(&detector->ProcessBaselineList);
        processBaseline = CONTAINING_RECORD(entry, AD_PROCESS_BASELINE, ListEntry);
        AdpFreeProcessBaseline(detector, processBaseline);
    }

    ExReleasePushLockExclusive(&detector->ProcessBaselineListLock);
    KeLeaveCriticalRegion();

    //
    // Free all anomalies
    //
    KeAcquireSpinLock(&Detector->AnomalyLock, &oldIrql);

    while (!IsListEmpty(&Detector->AnomalyList)) {
        entry = RemoveHeadList(&Detector->AnomalyList);
        anomaly = CONTAINING_RECORD(entry, AD_ANOMALY, ListEntry);
        ExFreeToNPagedLookasideList(&detector->AnomalyLookaside, anomaly);
    }

    KeReleaseSpinLock(&Detector->AnomalyLock, oldIrql);

    //
    // Free hash table
    //
    AdpFreeHashTable(
        &detector->ProcessHash.Buckets,
        detector->ProcessHash.BucketCount
    );

    //
    // Delete lookaside lists
    //
    if (detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&detector->BaselineLookaside);
        ExDeleteNPagedLookasideList(&detector->AnomalyLookaside);
        ExDeleteNPagedLookasideList(&detector->ProcessBaselineLookaside);
    }

    //
    // Free detector
    //
    ExFreePoolWithTag(detector, AD_POOL_TAG);
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
    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SigmaThreshold < AD_MIN_SIGMA_THRESHOLD ||
        SigmaThreshold > AD_MAX_SIGMA_THRESHOLD) {
        return STATUS_INVALID_PARAMETER;
    }

    Detector->SigmaThreshold = SigmaThreshold;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdRegisterCallback(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_ANOMALY_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAD_DETECTOR_INTERNAL detector;
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, AD_DETECTOR_INTERNAL, Public);

    //
    // First, set the primary callback if not set
    //
    if (Detector->Callback == NULL) {
        Detector->Callback = Callback;
        Detector->CallbackContext = Context;
        return STATUS_SUCCESS;
    }

    //
    // Try additional callback slots
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->CallbackLock);

    for (i = 0; i < AD_MAX_CALLBACKS; i++) {
        if (!detector->AdditionalCallbacks[i].InUse) {
            detector->AdditionalCallbacks[i].Callback = Callback;
            detector->AdditionalCallbacks[i].Context = Context;
            detector->AdditionalCallbacks[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&detector->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
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
    PAD_DETECTOR_INTERNAL detector;
    PAD_BASELINE globalBaseline;
    PAD_PROCESS_BASELINE processBaseline;

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Metric > AdMetric_Custom) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, AD_DETECTOR_INTERNAL, Public);

    //
    // Update global baseline
    //
    globalBaseline = AdpFindGlobalBaseline(Detector, Metric);
    if (globalBaseline != NULL) {
        AdpUpdateBaseline(globalBaseline, Value);
    }

    //
    // Update process-specific baseline if ProcessId is provided
    //
    if (ProcessId != NULL) {
        processBaseline = AdpFindProcessBaseline(detector, ProcessId);

        if (processBaseline == NULL) {
            processBaseline = AdpCreateProcessBaseline(detector, ProcessId);
        }

        if (processBaseline != NULL) {
            AdpUpdateBaseline(&processBaseline->Baselines[Metric], Value);
            AdpUpdateEMA(processBaseline, Metric, Value);
            KeQuerySystemTime(&processBaseline->LastActivityTime);
        }
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.SamplesProcessed);

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
    _Out_opt_ PAD_ANOMALY* Anomaly
    )
{
    PAD_DETECTOR_INTERNAL detector;
    PAD_BASELINE baseline = NULL;
    PAD_PROCESS_BASELINE processBaseline = NULL;
    PAD_ANOMALY anomaly = NULL;
    DOUBLE zScore;
    DOUBLE modifiedZScore;
    DOUBLE effectiveDeviation;
    BOOLEAN isAnomaly = FALSE;
    BOOLEAN useProcessBaseline = FALSE;

    if (Detector == NULL || !Detector->Initialized || IsAnomaly == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Metric > AdMetric_Custom) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsAnomaly = FALSE;
    if (Anomaly != NULL) {
        *Anomaly = NULL;
    }

    detector = CONTAINING_RECORD(Detector, AD_DETECTOR_INTERNAL, Public);

    //
    // Try process-specific baseline first
    //
    if (ProcessId != NULL) {
        processBaseline = AdpFindProcessBaseline(detector, ProcessId);

        if (processBaseline != NULL &&
            processBaseline->Baselines[Metric].SampleCount >= Detector->MinimumSamples) {
            baseline = &processBaseline->Baselines[Metric];
            useProcessBaseline = TRUE;
        }
    }

    //
    // Fall back to global baseline
    //
    if (baseline == NULL) {
        baseline = AdpFindGlobalBaseline(Detector, Metric);
    }

    if (baseline == NULL || baseline->SampleCount < Detector->MinimumSamples) {
        //
        // Not enough samples to detect anomalies
        //
        return STATUS_SUCCESS;
    }

    //
    // Calculate Z-score
    //
    zScore = AdpCalculateZScore(baseline, Value);

    //
    // Calculate Modified Z-score (MAD-based) for robustness
    //
    modifiedZScore = AdpCalculateModifiedZScore(baseline, Value);

    //
    // Use the more conservative of the two methods
    // This reduces false positives while catching true anomalies
    //
    effectiveDeviation = min(zScore, modifiedZScore);

    //
    // For very high deviations, use standard Z-score
    // (MAD can be unreliable for extreme outliers)
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
        // Create anomaly record
        //
        anomaly = AdpCreateAnomaly(
            detector,
            ProcessId,
            Metric,
            baseline,
            Value,
            effectiveDeviation
        );

        if (anomaly != NULL) {
            anomaly->IsHighConfidence = AdpIsHighConfidenceAnomaly(
                baseline,
                effectiveDeviation,
                Value
            );

            //
            // Add to anomaly list
            //
            AdpAddAnomalyToList(detector, anomaly);

            //
            // Notify callbacks
            //
            AdpNotifyCallbacks(detector, anomaly);

            //
            // Update statistics
            //
            InterlockedIncrement64(&Detector->Stats.AnomaliesDetected);

            if (Anomaly != NULL) {
                *Anomaly = anomaly;
            }
        }
    }

    //
    // Record the sample regardless of anomaly status
    //
    AdRecordSample(Detector, ProcessId, Metric, Value);

    *IsAnomaly = isAnomaly;

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
    _Out_ PAD_BASELINE* Baseline
    )
{
    PAD_DETECTOR_INTERNAL detector;
    PAD_PROCESS_BASELINE processBaseline;
    PAD_BASELINE baseline = NULL;

    if (Detector == NULL || !Detector->Initialized || Baseline == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Metric > AdMetric_Custom) {
        return STATUS_INVALID_PARAMETER;
    }

    *Baseline = NULL;

    detector = CONTAINING_RECORD(Detector, AD_DETECTOR_INTERNAL, Public);

    //
    // Try process-specific baseline first
    //
    if (ProcessId != NULL) {
        processBaseline = AdpFindProcessBaseline(detector, ProcessId);

        if (processBaseline != NULL) {
            baseline = &processBaseline->Baselines[Metric];
        }
    }

    //
    // Fall back to global baseline
    //
    if (baseline == NULL) {
        baseline = AdpFindGlobalBaseline(Detector, Metric);
    }

    if (baseline == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Baseline = baseline;

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
    _Out_writes_to_(Max, *Count) PAD_ANOMALY* Anomalies,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PLIST_ENTRY entry;
    PAD_ANOMALY anomaly;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    KIRQL oldIrql;
    ULONG count = 0;

    if (Detector == NULL || !Detector->Initialized ||
        Anomalies == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart - ((LONGLONG)MaxAgeSeconds * 10000000);

    KeAcquireSpinLock(&Detector->AnomalyLock, &oldIrql);

    for (entry = Detector->AnomalyList.Flink;
         entry != &Detector->AnomalyList && count < Max;
         entry = entry->Flink) {

        anomaly = CONTAINING_RECORD(entry, AD_ANOMALY, ListEntry);

        if (anomaly->DetectionTime.QuadPart >= cutoffTime.QuadPart) {
            Anomalies[count++] = anomaly;
        }
    }

    KeReleaseSpinLock(&Detector->AnomalyLock, oldIrql);

    *Count = count;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
AdFreeAnomaly(
    _In_ PAD_ANOMALY Anomaly
    )
{
    if (Anomaly == NULL) {
        return;
    }

    //
    // Free process name if allocated
    //
    if (Anomaly->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Anomaly->ProcessName.Buffer, AD_POOL_TAG);
    }

    ExFreePoolWithTag(Anomaly, AD_POOL_TAG);
}

// ============================================================================
// PRIVATE FUNCTIONS - TIMER
// ============================================================================

static VOID
AdpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PAD_DETECTOR_INTERNAL detector = (PAD_DETECTOR_INTERNAL)DeferredContext;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PAD_ANOMALY anomaly;
    PAD_PROCESS_BASELINE processBaseline;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    LARGE_INTEGER staleTime;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (detector == NULL || !detector->Public.Initialized) {
        return;
    }

    if (InterlockedCompareExchange(&detector->CleanupInProgress, 1, 0) != 0) {
        return;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Remove old anomalies (older than 1 hour)
    //
    cutoffTime.QuadPart = currentTime.QuadPart - ((LONGLONG)3600 * 10000000);

    KeAcquireSpinLock(&detector->Public.AnomalyLock, &oldIrql);

    for (entry = detector->Public.AnomalyList.Flink;
         entry != &detector->Public.AnomalyList;
         entry = next) {

        next = entry->Flink;
        anomaly = CONTAINING_RECORD(entry, AD_ANOMALY, ListEntry);

        if (anomaly->DetectionTime.QuadPart < cutoffTime.QuadPart) {
            RemoveEntryList(&anomaly->ListEntry);
            InterlockedDecrement(&detector->Public.AnomalyCount);

            //
            // Free in DPC - use tagged pool free
            //
            if (anomaly->ProcessName.Buffer != NULL) {
                ExFreePoolWithTag(anomaly->ProcessName.Buffer, AD_POOL_TAG);
            }
            ExFreeToNPagedLookasideList(&detector->AnomalyLookaside, anomaly);
        }
    }

    KeReleaseSpinLock(&detector->Public.AnomalyLock, oldIrql);

    //
    // Remove stale process baselines (no activity for 1 hour)
    //
    staleTime.QuadPart = currentTime.QuadPart - ((LONGLONG)AD_STALE_BASELINE_AGE_MS * 10000);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->ProcessBaselineListLock);
    ExAcquirePushLockExclusive(&detector->ProcessHash.Lock);

    for (entry = detector->ProcessBaselineList.Flink;
         entry != &detector->ProcessBaselineList;
         entry = next) {

        next = entry->Flink;
        processBaseline = CONTAINING_RECORD(entry, AD_PROCESS_BASELINE, ListEntry);

        if (processBaseline->LastActivityTime.QuadPart < staleTime.QuadPart &&
            processBaseline->RefCount <= 0) {

            RemoveEntryList(&processBaseline->ListEntry);
            RemoveEntryList(&processBaseline->HashEntry);
            InterlockedDecrement(&detector->ProcessBaselineCount);

            AdpFreeProcessBaseline(detector, processBaseline);
        }
    }

    ExReleasePushLockExclusive(&detector->ProcessHash.Lock);
    ExReleasePushLockExclusive(&detector->ProcessBaselineListLock);
    KeLeaveCriticalRegion();

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

    buckets = (LIST_ENTRY*)ExAllocatePoolWithTag(
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
    _Inout_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    UNREFERENCED_PARAMETER(BucketCount);

    if (*Buckets != NULL) {
        ExFreePoolWithTag(*Buckets, AD_POOL_TAG);
        *Buckets = NULL;
    }
}

static ULONG
AdpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    //
    // Simple hash function for process IDs
    //
    pid = ((pid >> 16) ^ pid) * 0x45d9f3b;
    pid = ((pid >> 16) ^ pid) * 0x45d9f3b;
    pid = (pid >> 16) ^ pid;

    return (ULONG)pid;
}

// ============================================================================
// PRIVATE FUNCTIONS - BASELINE MANAGEMENT
// ============================================================================

static PAD_BASELINE
AdpFindGlobalBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_METRIC_TYPE Metric
    )
{
    PLIST_ENTRY entry;
    PAD_BASELINE baseline;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->GlobalBaselineLock);

    for (entry = Detector->GlobalBaselines.Flink;
         entry != &Detector->GlobalBaselines;
         entry = entry->Flink) {

        baseline = CONTAINING_RECORD(entry, AD_BASELINE, ListEntry);

        if (baseline->Type == Metric) {
            ExReleasePushLockShared(&Detector->GlobalBaselineLock);
            KeLeaveCriticalRegion();
            return baseline;
        }
    }

    ExReleasePushLockShared(&Detector->GlobalBaselineLock);
    KeLeaveCriticalRegion();

    return NULL;
}

static PAD_BASELINE
AdpCreateGlobalBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ AD_METRIC_TYPE Metric
    )
{
    PAD_BASELINE baseline;

    baseline = (PAD_BASELINE)ExAllocateFromNPagedLookasideList(
        &Detector->BaselineLookaside
    );

    if (baseline == NULL) {
        return NULL;
    }

    RtlZeroMemory(baseline, sizeof(AD_BASELINE));
    baseline->Type = Metric;
    KeQuerySystemTime(&baseline->LastUpdated);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->Public.GlobalBaselineLock);

    InsertTailList(&Detector->Public.GlobalBaselines, &baseline->ListEntry);

    ExReleasePushLockExclusive(&Detector->Public.GlobalBaselineLock);
    KeLeaveCriticalRegion();

    return baseline;
}

static PAD_PROCESS_BASELINE
AdpFindProcessBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    )
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PAD_PROCESS_BASELINE processBaseline;

    hash = AdpHashProcessId(ProcessId);
    bucket = hash % Detector->ProcessHash.BucketCount;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ProcessHash.Lock);

    for (entry = Detector->ProcessHash.Buckets[bucket].Flink;
         entry != &Detector->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        processBaseline = CONTAINING_RECORD(entry, AD_PROCESS_BASELINE, HashEntry);

        if (processBaseline->ProcessId == ProcessId) {
            ExReleasePushLockShared(&Detector->ProcessHash.Lock);
            KeLeaveCriticalRegion();
            return processBaseline;
        }
    }

    ExReleasePushLockShared(&Detector->ProcessHash.Lock);
    KeLeaveCriticalRegion();

    return NULL;
}

static PAD_PROCESS_BASELINE
AdpCreateProcessBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId
    )
{
    PAD_PROCESS_BASELINE processBaseline;
    ULONG hash;
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
    KeQuerySystemTime(&processBaseline->CreateTime);
    processBaseline->LastActivityTime = processBaseline->CreateTime;

    //
    // Initialize per-metric baselines
    //
    for (i = 0; i <= AdMetric_Custom; i++) {
        processBaseline->Baselines[i].Type = (AD_METRIC_TYPE)i;
    }

    processBaseline->BaselineCount = AdMetric_Custom + 1;

    hash = AdpHashProcessId(ProcessId);
    bucket = hash % Detector->ProcessHash.BucketCount;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessBaselineListLock);
    ExAcquirePushLockExclusive(&Detector->ProcessHash.Lock);

    InsertTailList(&Detector->ProcessBaselineList, &processBaseline->ListEntry);
    InsertTailList(&Detector->ProcessHash.Buckets[bucket], &processBaseline->HashEntry);
    InterlockedIncrement(&Detector->ProcessBaselineCount);

    ExReleasePushLockExclusive(&Detector->ProcessHash.Lock);
    ExReleasePushLockExclusive(&Detector->ProcessBaselineListLock);
    KeLeaveCriticalRegion();

    return processBaseline;
}

static VOID
AdpFreeProcessBaseline(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _Inout_ PAD_PROCESS_BASELINE ProcessBaseline
    )
{
    if (ProcessBaseline->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(ProcessBaseline->ProcessName.Buffer, AD_POOL_TAG);
    }

    ExFreeToNPagedLookasideList(&Detector->ProcessBaselineLookaside, ProcessBaseline);
}

// ============================================================================
// PRIVATE FUNCTIONS - BASELINE UPDATE
// ============================================================================

static VOID
AdpUpdateBaseline(
    _Inout_ PAD_BASELINE Baseline,
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
    // Update min/max
    //
    if (Baseline->SampleCount == 1) {
        Baseline->Min = Value;
        Baseline->Max = Value;
    } else {
        if (Value < Baseline->Min) {
            Baseline->Min = Value;
        }
        if (Value > Baseline->Max) {
            Baseline->Max = Value;
        }
    }

    //
    // Recalculate statistics periodically
    //
    if (Baseline->SampleCount % 10 == 0 || Baseline->SampleCount < 20) {
        AdpCalculateStatistics(Baseline);
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

static VOID
AdpCalculateStatistics(
    _Inout_ PAD_BASELINE Baseline
    )
{
    ULONG count;
    ULONG i;
    DOUBLE sum = 0.0;
    DOUBLE sumSquares = 0.0;
    DOUBLE mean;
    DOUBLE variance;

    count = Baseline->SampleCount;
    if (count == 0) {
        return;
    }

    //
    // Calculate mean
    //
    for (i = 0; i < count; i++) {
        sum += Baseline->Samples[i];
    }
    mean = sum / (DOUBLE)count;
    Baseline->Mean = mean;

    //
    // Calculate standard deviation
    //
    for (i = 0; i < count; i++) {
        DOUBLE diff = Baseline->Samples[i] - mean;
        sumSquares += diff * diff;
    }

    variance = sumSquares / (DOUBLE)count;
    Baseline->StandardDeviation = sqrt(variance);
}

// ============================================================================
// PRIVATE FUNCTIONS - STATISTICAL CALCULATIONS
// ============================================================================

static DOUBLE
AdpCalculateZScore(
    _In_ PAD_BASELINE Baseline,
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
    // Return absolute value (we care about deviation in either direction)
    //
    return (zScore < 0.0) ? -zScore : zScore;
}

static DOUBLE
AdpCalculateModifiedZScore(
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE Value
    )
{
    DOUBLE sortedSamples[AD_BASELINE_SAMPLES];
    DOUBLE median;
    DOUBLE mad;
    DOUBLE modifiedZScore;
    ULONG count;

    count = Baseline->SampleCount;
    if (count < 3) {
        return AdpCalculateZScore(Baseline, Value);
    }

    //
    // Copy samples for sorting
    //
    RtlCopyMemory(sortedSamples, Baseline->Samples, count * sizeof(DOUBLE));

    //
    // Calculate median
    //
    median = AdpCalculateMedian(sortedSamples, count);

    //
    // Calculate MAD (Median Absolute Deviation)
    //
    mad = AdpCalculateMAD(sortedSamples, count, median);

    if (mad < 0.0001) {
        //
        // If MAD is essentially zero, fall back to Z-score
        //
        return AdpCalculateZScore(Baseline, Value);
    }

    //
    // Calculate modified Z-score
    //
    modifiedZScore = AD_MAD_CONSTANT * (Value - median) / mad;

    return (modifiedZScore < 0.0) ? -modifiedZScore : modifiedZScore;
}

static DOUBLE
AdpCalculateMedian(
    _In_ DOUBLE* Array,
    _In_ ULONG Count
    )
{
    AdpQuickSortDouble(Array, Count);

    if (Count % 2 == 0) {
        return (Array[Count / 2 - 1] + Array[Count / 2]) / 2.0;
    } else {
        return Array[Count / 2];
    }
}

static DOUBLE
AdpCalculateMAD(
    _In_ DOUBLE* Array,
    _In_ ULONG Count,
    _In_ DOUBLE Median
    )
{
    DOUBLE deviations[AD_BASELINE_SAMPLES];
    ULONG i;

    for (i = 0; i < Count; i++) {
        DOUBLE diff = Array[i] - Median;
        deviations[i] = (diff < 0.0) ? -diff : diff;
    }

    return AdpCalculateMedian(deviations, Count);
}

static VOID
AdpQuickSortDouble(
    _Inout_ DOUBLE* Array,
    _In_ ULONG Count
    )
{
    ULONG i, j;
    DOUBLE temp;

    //
    // Simple insertion sort for small arrays
    //
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

    return (baseScore * metricMultiplier) / 100;
}

static BOOLEAN
AdpIsHighConfidenceAnomaly(
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE DeviationSigmas,
    _In_ DOUBLE Value
    )
{
    //
    // High confidence if:
    // 1. Deviation is very high (>4 sigma)
    // 2. Value is significantly beyond observed range
    // 3. We have sufficient samples
    //
    if (DeviationSigmas >= AD_HIGH_CONFIDENCE_SIGMA) {
        return TRUE;
    }

    if (Baseline->SampleCount >= 100 && DeviationSigmas >= AD_DEFAULT_SIGMA_THRESHOLD) {
        //
        // Check if value is beyond observed range with margin
        //
        DOUBLE range = Baseline->Max - Baseline->Min;
        if (range > 0.0) {
            DOUBLE margin = range * 0.2;
            if (Value < (Baseline->Min - margin) ||
                Value > (Baseline->Max + margin)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static PAD_ANOMALY
AdpCreateAnomaly(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _In_ PAD_BASELINE Baseline,
    _In_ DOUBLE ObservedValue,
    _In_ DOUBLE DeviationSigmas
    )
{
    PAD_ANOMALY anomaly;

    anomaly = (PAD_ANOMALY)ExAllocateFromNPagedLookasideList(
        &Detector->AnomalyLookaside
    );

    if (anomaly == NULL) {
        return NULL;
    }

    RtlZeroMemory(anomaly, sizeof(AD_ANOMALY));

    anomaly->ProcessId = ProcessId;
    anomaly->MetricType = Metric;
    anomaly->ObservedValue = ObservedValue;
    anomaly->ExpectedValue = Baseline->Mean;
    anomaly->DeviationSigmas = DeviationSigmas;
    anomaly->SeverityScore = AdpCalculateSeverityScore(DeviationSigmas, Metric);

    KeQuerySystemTime(&anomaly->DetectionTime);

    return anomaly;
}

static VOID
AdpAddAnomalyToList(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ PAD_ANOMALY Anomaly
    )
{
    KIRQL oldIrql;

    //
    // Check limit
    //
    if (Detector->Public.AnomalyCount >= AD_MAX_ANOMALIES) {
        //
        // Remove oldest anomaly
        //
        PLIST_ENTRY oldest;
        PAD_ANOMALY oldAnomaly;

        KeAcquireSpinLock(&Detector->Public.AnomalyLock, &oldIrql);

        if (!IsListEmpty(&Detector->Public.AnomalyList)) {
            oldest = RemoveHeadList(&Detector->Public.AnomalyList);
            oldAnomaly = CONTAINING_RECORD(oldest, AD_ANOMALY, ListEntry);
            InterlockedDecrement(&Detector->Public.AnomalyCount);
            ExFreeToNPagedLookasideList(&Detector->AnomalyLookaside, oldAnomaly);
        }

        InsertTailList(&Detector->Public.AnomalyList, &Anomaly->ListEntry);
        InterlockedIncrement(&Detector->Public.AnomalyCount);

        KeReleaseSpinLock(&Detector->Public.AnomalyLock, oldIrql);
    } else {
        KeAcquireSpinLock(&Detector->Public.AnomalyLock, &oldIrql);

        InsertTailList(&Detector->Public.AnomalyList, &Anomaly->ListEntry);
        InterlockedIncrement(&Detector->Public.AnomalyCount);

        KeReleaseSpinLock(&Detector->Public.AnomalyLock, oldIrql);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACKS
// ============================================================================

static VOID
AdpNotifyCallbacks(
    _In_ PAD_DETECTOR_INTERNAL Detector,
    _In_ PAD_ANOMALY Anomaly
    )
{
    ULONG i;

    //
    // Primary callback
    //
    if (Detector->Public.Callback != NULL) {
        Detector->Public.Callback(Anomaly, Detector->Public.CallbackContext);
    }

    //
    // Additional callbacks
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < AD_MAX_CALLBACKS; i++) {
        if (Detector->AdditionalCallbacks[i].InUse &&
            Detector->AdditionalCallbacks[i].Callback != NULL) {

            Detector->AdditionalCallbacks[i].Callback(
                Anomaly,
                Detector->AdditionalCallbacks[i].Context
            );
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE FUNCTIONS - UTILITIES
// ============================================================================

static const CHAR*
AdpMetricTypeToString(
    _In_ AD_METRIC_TYPE Metric
    )
{
    switch (Metric) {
        case AdMetric_CPUUsage:
            return "CPUUsage";
        case AdMetric_MemoryUsage:
            return "MemoryUsage";
        case AdMetric_FileOperations:
            return "FileOperations";
        case AdMetric_NetworkConnections:
            return "NetworkConnections";
        case AdMetric_RegistryOperations:
            return "RegistryOperations";
        case AdMetric_ProcessCreation:
            return "ProcessCreation";
        case AdMetric_ThreadCreation:
            return "ThreadCreation";
        case AdMetric_DLLLoads:
            return "DLLLoads";
        case AdMetric_HandleCount:
            return "HandleCount";
        case AdMetric_PrivilegeUse:
            return "PrivilegeUse";
        case AdMetric_Custom:
            return "Custom";
        default:
            return "Unknown";
    }
}

//
// Provide sqrt implementation for kernel mode
//
#ifndef sqrt
static DOUBLE
sqrt(
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

    guess = Value / 2.0;

    do {
        prev = guess;
        guess = (guess + Value / guess) / 2.0;
        iterations++;
    } while ((guess - prev > 0.0001 || prev - guess > 0.0001) && iterations < 50);

    return guess;
}
#endif
