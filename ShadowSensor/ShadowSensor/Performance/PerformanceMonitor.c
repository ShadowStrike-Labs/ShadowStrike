/*++
    ShadowStrike Next-Generation Antivirus
    Module: PerformanceMonitor.c

    Purpose: Enterprise-grade self-monitoring for kernel driver performance.

    Architecture:
    - Per-metric ring buffers (fixed-size arrays, lock-free-friendly)
    - KSPIN_LOCK per ring buffer for DISPATCH_LEVEL safety
    - Integer-only statistics (no floating point in kernel)
    - DPC-based periodic collection with threshold checking
    - Proper lifecycle with drain on shutdown

    Lock Ordering:
    - MetricBuffers[i].Lock (spin lock, DISPATCH_LEVEL) — leaf locks, independent
    - ThresholdLock (spin lock) — never held while holding a metric buffer lock

    Memory:
    - Monitor structure: NonPagedPoolNx
    - Ring buffer arrays: NonPagedPoolNx
    - All allocations bounded; no unbounded growth

    Copyright (c) ShadowStrike Team
--*/

#include "PerformanceMonitor.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SsPmInitialize)
#pragma alloc_text(PAGE, SsPmShutdown)
#pragma alloc_text(PAGE, SsPmGetStats)
#pragma alloc_text(PAGE, SsPmSetThreshold)
#pragma alloc_text(PAGE, SsPmRegisterAlertCallback)
#pragma alloc_text(PAGE, SsPmEnableCollection)
#pragma alloc_text(PAGE, SsPmDisableCollection)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define SSPM_DEFAULT_RING_CAPACITY    1024     // Samples per metric
#define SSPM_MAX_RING_CAPACITY        65536
#define SSPM_MIN_COLLECTION_INTERVAL  100      // 100ms minimum
#define SSPM_MAX_COLLECTION_INTERVAL  60000    // 60s maximum
#define SSPM_SHUTDOWN_SIGNATURE       0xDEADPM0F
#define SSPM_QPC_UNINITIALIZED        0

//=============================================================================
// Internal Structures
//=============================================================================

//
// Per-metric ring buffer
//
typedef struct _SSPM_RING_BUFFER {
    PSSPM_SAMPLE Samples;         // Fixed-size array, NonPagedPoolNx
    ULONG Capacity;               // Array element count
    ULONG Head;                   // Next write index
    ULONG Count;                  // Current fill level (<= Capacity)
    KSPIN_LOCK Lock;              // Protects all fields above
} SSPM_RING_BUFFER, *PSSPM_RING_BUFFER;

//
// Per-metric threshold
//
typedef struct _SSPM_THRESHOLD {
    BOOLEAN Enabled;
    ULONG64 Value;
} SSPM_THRESHOLD, *PSSPM_THRESHOLD;

//
// Full monitor structure (opaque definition)
//
struct _SSPM_MONITOR {
    volatile LONG Initialized;
    volatile LONG ShuttingDown;
    volatile LONG ActiveOperations;   // Drain counter for shutdown
    KEVENT DrainEvent;

    //
    // Ring buffers — one per metric type
    //
    SSPM_RING_BUFFER MetricBuffers[SsPmMetric_Count];

    //
    // Thresholds — protected by ThresholdLock
    //
    SSPM_THRESHOLD Thresholds[SsPmMetric_Count];
    KSPIN_LOCK ThresholdLock;

    //
    // Alert callback — volatile pointer, read atomically
    //
    SSPM_ALERT_CALLBACK AlertCallback;
    PVOID AlertContext;
    KSPIN_LOCK CallbackLock;

    //
    // Periodic collection timer + DPC
    //
    KTIMER CollectionTimer;
    KDPC CollectionDpc;
    ULONG CollectionIntervalMs;
    volatile LONG CollectionEnabled;

    //
    // QPC frequency for latency conversion
    //
    LARGE_INTEGER QpcFrequency;

    //
    // Global statistics
    //
    struct {
        volatile LONG64 TotalSamplesRecorded;
        volatile LONG64 AlertsTriggered;
        LARGE_INTEGER StartTime;
    } Stats;
};


//=============================================================================
// Forward Declarations
//=============================================================================

static KDEFERRED_ROUTINE SspmiCollectionDpc;

static VOID
SspmiCheckThresholds(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ ULONG64 Value
    );

//=============================================================================
// Operation Guard (drain support for shutdown)
//=============================================================================

static
FORCEINLINE
BOOLEAN
SspmiAcquireOperation(
    _In_ PSSPM_MONITOR Monitor
    )
{
    if (InterlockedCompareExchange(&Monitor->ShuttingDown, 0, 0) != 0) {
        return FALSE;
    }
    InterlockedIncrement(&Monitor->ActiveOperations);
    if (InterlockedCompareExchange(&Monitor->ShuttingDown, 0, 0) != 0) {
        if (InterlockedDecrement(&Monitor->ActiveOperations) == 0) {
            KeSetEvent(&Monitor->DrainEvent, IO_NO_INCREMENT, FALSE);
        }
        return FALSE;
    }
    return TRUE;
}

static
FORCEINLINE
VOID
SspmiReleaseOperation(
    _In_ PSSPM_MONITOR Monitor
    )
{
    if (InterlockedDecrement(&Monitor->ActiveOperations) == 0) {
        KeSetEvent(&Monitor->DrainEvent, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// Metric Validation
//=============================================================================

static
FORCEINLINE
BOOLEAN
SspmiIsValidMetric(
    _In_ SSPM_METRIC_TYPE Metric
    )
{
    return (ULONG)Metric < (ULONG)SsPmMetric_Count;
}


//=============================================================================
// Integer-Only Sort for Percentile Computation
//=============================================================================

//
// Simple insertion sort for small arrays (used on snapshot copies only).
// Called at <= APC_LEVEL with a bounded-size stack/heap buffer.
//
static
VOID
SspmiSortValues(
    _Inout_updates_(Count) ULONG64* Values,
    _In_ ULONG Count
    )
{
    ULONG i, j;
    ULONG64 Key;

    for (i = 1; i < Count; i++) {
        Key = Values[i];
        j = i;
        while (j > 0 && Values[j - 1] > Key) {
            Values[j] = Values[j - 1];
            j--;
        }
        Values[j] = Key;
    }
}

//=============================================================================
// Public API: Initialize
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmInitialize(
    _Out_ PSSPM_MONITOR* Monitor
    )
{
    PSSPM_MONITOR Mon = NULL;
    ULONG i;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    Mon = (PSSPM_MONITOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(SSPM_MONITOR), SSPM_POOL_TAG);
    if (Mon == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Mon, sizeof(SSPM_MONITOR));

    KeInitializeEvent(&Mon->DrainEvent, NotificationEvent, TRUE);
    KeInitializeSpinLock(&Mon->ThresholdLock);
    KeInitializeSpinLock(&Mon->CallbackLock);

    //
    // Get QPC frequency for latency conversions
    //
    KeQueryPerformanceCounter(&Mon->QpcFrequency);

    //
    // Allocate ring buffers for each metric
    //
    for (i = 0; i < SsPmMetric_Count; i++) {
        KeInitializeSpinLock(&Mon->MetricBuffers[i].Lock);
        Mon->MetricBuffers[i].Capacity = SSPM_DEFAULT_RING_CAPACITY;
        Mon->MetricBuffers[i].Head = 0;
        Mon->MetricBuffers[i].Count = 0;

        Mon->MetricBuffers[i].Samples = (PSSPM_SAMPLE)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            (SIZE_T)SSPM_DEFAULT_RING_CAPACITY * sizeof(SSPM_SAMPLE),
            SSPM_POOL_TAG_SAMPLE);

        if (Mon->MetricBuffers[i].Samples == NULL) {
            //
            // Cleanup already-allocated buffers
            //
            ULONG j;
            for (j = 0; j < i; j++) {
                ShadowStrikeFreePoolWithTag(
                    Mon->MetricBuffers[j].Samples, SSPM_POOL_TAG_SAMPLE);
            }
            ShadowStrikeFreePoolWithTag(Mon, SSPM_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(Mon->MetricBuffers[i].Samples,
            (SIZE_T)SSPM_DEFAULT_RING_CAPACITY * sizeof(SSPM_SAMPLE));
    }

    //
    // Initialize timer + DPC (but don't start yet)
    //
    KeInitializeTimer(&Mon->CollectionTimer);
    KeInitializeDpc(&Mon->CollectionDpc, SspmiCollectionDpc, Mon);

    KeQuerySystemTime(&Mon->Stats.StartTime);

    InterlockedExchange(&Mon->Initialized, 1);

    *Monitor = Mon;
    return STATUS_SUCCESS;
}


//=============================================================================
// Public API: Shutdown
//=============================================================================

_Use_decl_annotations_
VOID
SsPmShutdown(
    _Inout_ PSSPM_MONITOR Monitor
    )
{
    ULONG i;
    LARGE_INTEGER Timeout;

    PAGED_CODE();

    if (Monitor == NULL ||
        InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0) {
        return;
    }

    //
    // Phase 1: Signal shutdown — reject new operations
    //
    InterlockedExchange(&Monitor->ShuttingDown, 1);
    InterlockedExchange(&Monitor->Initialized, 0);

    //
    // Phase 2: Stop collection timer and flush DPCs
    //
    KeCancelTimer(&Monitor->CollectionTimer);
    KeFlushQueuedDpcs();

    //
    // Phase 3: Wait for in-flight operations to drain
    //
    if (InterlockedCompareExchange(&Monitor->ActiveOperations, 0, 0) > 0) {
        Timeout.QuadPart = -(5LL * 10000000LL);  // 5 seconds
        KeClearEvent(&Monitor->DrainEvent);
        KeWaitForSingleObject(
            &Monitor->DrainEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout);
    }

    //
    // Phase 4: Free all ring buffer arrays
    //
    for (i = 0; i < SsPmMetric_Count; i++) {
        if (Monitor->MetricBuffers[i].Samples != NULL) {
            ShadowStrikeFreePoolWithTag(
                Monitor->MetricBuffers[i].Samples, SSPM_POOL_TAG_SAMPLE);
            Monitor->MetricBuffers[i].Samples = NULL;
        }
    }

    //
    // Phase 5: Free monitor structure
    //
    ShadowStrikeFreePoolWithTag(Monitor, SSPM_POOL_TAG);
}


//=============================================================================
// Public API: Record Sample
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmRecordSample(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ ULONG64 Value
    )
/*++
Routine Description:
    Records a single metric sample into the ring buffer.
    Safe to call at DISPATCH_LEVEL (uses spin lock).
--*/
{
    PSSPM_RING_BUFFER Ring;
    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime;

    if (Monitor == NULL || !SspmiIsValidMetric(Metric)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SspmiAcquireOperation(Monitor)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Ring = &Monitor->MetricBuffers[(ULONG)Metric];
    KeQuerySystemTime(&CurrentTime);

    KeAcquireSpinLock(&Ring->Lock, &OldIrql);

    //
    // Write into ring buffer at head position
    //
    Ring->Samples[Ring->Head].Timestamp = CurrentTime;
    Ring->Samples[Ring->Head].Value = Value;

    Ring->Head = (Ring->Head + 1) % Ring->Capacity;
    if (Ring->Count < Ring->Capacity) {
        Ring->Count++;
    }

    KeReleaseSpinLock(&Ring->Lock, OldIrql);

    InterlockedIncrement64(&Monitor->Stats.TotalSamplesRecorded);

    //
    // Check thresholds (at current IRQL, which may be DISPATCH_LEVEL)
    //
    SspmiCheckThresholds(Monitor, Metric, Value);

    SspmiReleaseOperation(Monitor);

    return STATUS_SUCCESS;
}

//=============================================================================
// Public API: Record Latency (from QPC start tick)
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmRecordLatency(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ LARGE_INTEGER StartTick
    )
/*++
Routine Description:
    Computes elapsed time since StartTick (from KeQueryPerformanceCounter)
    and records it as microseconds.
--*/
{
    LARGE_INTEGER EndTick;
    LARGE_INTEGER Freq;
    ULONG64 ElapsedUs;

    if (Monitor == NULL || !SspmiIsValidMetric(Metric)) {
        return STATUS_INVALID_PARAMETER;
    }

    EndTick = KeQueryPerformanceCounter(&Freq);

    //
    // Guard against backward time or zero frequency
    //
    if (Freq.QuadPart == 0 || EndTick.QuadPart <= StartTick.QuadPart) {
        return SsPmRecordSample(Monitor, Metric, 0);
    }

    //
    // Convert QPC ticks to microseconds:
    // ElapsedUs = (EndTick - StartTick) * 1,000,000 / Frequency
    //
    // To avoid overflow with large tick deltas, divide first if possible:
    //
    {
        ULONG64 DeltaTicks = (ULONG64)(EndTick.QuadPart - StartTick.QuadPart);
        ULONG64 FreqVal = (ULONG64)Freq.QuadPart;

        if (DeltaTicks <= (MAXULONG64 / 1000000ULL)) {
            ElapsedUs = (DeltaTicks * 1000000ULL) / FreqVal;
        } else {
            // Large delta: divide first, lose sub-microsecond precision
            ElapsedUs = (DeltaTicks / FreqVal) * 1000000ULL;
        }
    }

    return SsPmRecordSample(Monitor, Metric, ElapsedUs);
}


//=============================================================================
// Public API: Get Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmGetStats(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _Out_ PSSPM_METRIC_STATS Stats
    )
/*++
Routine Description:
    Computes statistics from the ring buffer for the given metric.
    Takes a snapshot under spin lock, then computes offline.
    Uses a heap-allocated scratch buffer for sorting (percentiles).
--*/
{
    PSSPM_RING_BUFFER Ring;
    KIRQL OldIrql;
    ULONG SnapCount;
    ULONG AllocCount;     // Size of SortBuf allocation (in elements)
    PULONG64 SortBuf = NULL;
    ULONG i, Index;
    ULONG64 Sum;

    PAGED_CODE();

    if (Monitor == NULL || Stats == NULL || !SspmiIsValidMetric(Metric)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(SSPM_METRIC_STATS));
    Stats->Type = Metric;

    Ring = &Monitor->MetricBuffers[(ULONG)Metric];

    //
    // Take snapshot under spin lock (brief hold — just copy count and values)
    //
    KeAcquireSpinLock(&Ring->Lock, &OldIrql);
    SnapCount = Ring->Count;

    if (SnapCount == 0) {
        KeReleaseSpinLock(&Ring->Lock, OldIrql);
        return STATUS_SUCCESS;
    }

    //
    // Release lock to allocate scratch buffer at PASSIVE_LEVEL,
    // then re-acquire. Allocate based on Capacity (upper bound).
    //
    KeReleaseSpinLock(&Ring->Lock, OldIrql);

    //
    // Allocate based on ring capacity (upper bound) so we never
    // need to worry about count growing between release and re-acquire.
    //
    AllocCount = Ring->Capacity;
    SortBuf = (PULONG64)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        (SIZE_T)AllocCount * sizeof(ULONG64),
        SSPM_POOL_TAG);
    if (SortBuf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Re-acquire and re-snapshot (count may have changed)
    //
    KeAcquireSpinLock(&Ring->Lock, &OldIrql);
    SnapCount = Ring->Count;

    if (SnapCount == 0) {
        KeReleaseSpinLock(&Ring->Lock, OldIrql);
        ShadowStrikeFreePoolWithTag(SortBuf, SSPM_POOL_TAG);
        return STATUS_SUCCESS;
    }

    //
    // Cap to allocation size and ring capacity
    //
    if (SnapCount > AllocCount) {
        SnapCount = AllocCount;
    }
    if (SnapCount > Ring->Capacity) {
        SnapCount = Ring->Capacity;
    }

    //
    // Copy values out of ring buffer into sort buffer.
    // Ring buffer may be partially filled, so we iterate from
    // (Head - Count) modulo Capacity through to (Head - 1).
    //
    Stats->Min = MAXULONG64;
    Stats->Max = 0;
    Sum = 0;
    Stats->OldestSampleTime.QuadPart = MAXLONGLONG;
    Stats->NewestSampleTime.QuadPart = 0;

    for (i = 0; i < SnapCount; i++) {
        Index = (Ring->Head + Ring->Capacity - SnapCount + i) % Ring->Capacity;
        SortBuf[i] = Ring->Samples[Index].Value;
        Sum += SortBuf[i];

        if (SortBuf[i] < Stats->Min) Stats->Min = SortBuf[i];
        if (SortBuf[i] > Stats->Max) Stats->Max = SortBuf[i];

        if (Ring->Samples[Index].Timestamp.QuadPart < Stats->OldestSampleTime.QuadPart) {
            Stats->OldestSampleTime = Ring->Samples[Index].Timestamp;
        }
        if (Ring->Samples[Index].Timestamp.QuadPart > Stats->NewestSampleTime.QuadPart) {
            Stats->NewestSampleTime = Ring->Samples[Index].Timestamp;
        }
    }

    KeReleaseSpinLock(&Ring->Lock, OldIrql);

    //
    // Compute statistics on the snapshot (no lock needed)
    //
    Stats->SampleCount = (ULONG64)SnapCount;
    Stats->Mean = Sum / (ULONG64)SnapCount;

    //
    // Sort for percentiles
    //
    SspmiSortValues(SortBuf, SnapCount);

    if (SnapCount >= 20) {
        // p95 = value at index floor(0.95 * count)
        Stats->Percentile95 = SortBuf[(ULONG)((ULONG64)SnapCount * 95 / 100)];
        Stats->Percentile99 = SortBuf[(ULONG)((ULONG64)SnapCount * 99 / 100)];
    } else {
        // Too few samples for meaningful percentiles; use max
        Stats->Percentile95 = Stats->Max;
        Stats->Percentile99 = Stats->Max;
    }

    ShadowStrikeFreePoolWithTag(SortBuf, SSPM_POOL_TAG);
    return STATUS_SUCCESS;
}


//=============================================================================
// Public API: Set Threshold
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmSetThreshold(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ ULONG64 ThresholdValue
    )
{
    KIRQL OldIrql;

    PAGED_CODE();

    if (Monitor == NULL || !SspmiIsValidMetric(Metric)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Monitor->ThresholdLock, &OldIrql);

    Monitor->Thresholds[(ULONG)Metric].Value = ThresholdValue;
    Monitor->Thresholds[(ULONG)Metric].Enabled = TRUE;

    KeReleaseSpinLock(&Monitor->ThresholdLock, OldIrql);

    return STATUS_SUCCESS;
}

//=============================================================================
// Public API: Register Alert Callback
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmRegisterAlertCallback(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    KIRQL OldIrql;

    PAGED_CODE();

    if (Monitor == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Monitor->CallbackLock, &OldIrql);

    Monitor->AlertCallback = Callback;
    Monitor->AlertContext = Context;

    KeReleaseSpinLock(&Monitor->CallbackLock, OldIrql);

    return STATUS_SUCCESS;
}

//=============================================================================
// Public API: Enable / Disable Collection
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPmEnableCollection(
    _In_ PSSPM_MONITOR Monitor,
    _In_ ULONG IntervalMs
    )
{
    LARGE_INTEGER DueTime;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (IntervalMs < SSPM_MIN_COLLECTION_INTERVAL ||
        IntervalMs > SSPM_MAX_COLLECTION_INTERVAL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Cancel any existing timer first
    //
    KeCancelTimer(&Monitor->CollectionTimer);
    KeFlushQueuedDpcs();

    Monitor->CollectionIntervalMs = IntervalMs;

    DueTime.QuadPart = -((LONGLONG)IntervalMs * 10000);
    KeSetTimerEx(
        &Monitor->CollectionTimer,
        DueTime,
        IntervalMs,
        &Monitor->CollectionDpc);

    InterlockedExchange(&Monitor->CollectionEnabled, 1);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SsPmDisableCollection(
    _In_ PSSPM_MONITOR Monitor
    )
{
    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedExchange(&Monitor->CollectionEnabled, 0);

    KeCancelTimer(&Monitor->CollectionTimer);
    KeFlushQueuedDpcs();

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal: Threshold Checking
//=============================================================================

static
VOID
SspmiCheckThresholds(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ ULONG64 Value
    )
/*++
Routine Description:
    Checks whether the recorded value exceeds the threshold for this metric.
    If so, invokes the alert callback (if registered).
    Safe at DISPATCH_LEVEL — uses spin locks only.
--*/
{
    KIRQL OldIrql;
    BOOLEAN Exceeded = FALSE;
    ULONG64 Threshold = 0;
    SSPM_ALERT_CALLBACK Cb = NULL;
    PVOID CbCtx = NULL;
    SSPM_THRESHOLD_ALERT Alert;

    //
    // Read threshold (under spin lock)
    //
    KeAcquireSpinLock(&Monitor->ThresholdLock, &OldIrql);

    if (Monitor->Thresholds[(ULONG)Metric].Enabled &&
        Value > Monitor->Thresholds[(ULONG)Metric].Value) {
        Exceeded = TRUE;
        Threshold = Monitor->Thresholds[(ULONG)Metric].Value;
    }

    KeReleaseSpinLock(&Monitor->ThresholdLock, OldIrql);

    if (!Exceeded) {
        return;
    }

    //
    // Read callback pointer (under spin lock)
    //
    KeAcquireSpinLock(&Monitor->CallbackLock, &OldIrql);
    Cb = Monitor->AlertCallback;
    CbCtx = Monitor->AlertContext;
    KeReleaseSpinLock(&Monitor->CallbackLock, OldIrql);

    if (Cb == NULL) {
        return;
    }

    //
    // Build alert on stack and invoke callback
    //
    RtlZeroMemory(&Alert, sizeof(Alert));
    Alert.Metric = Metric;
    Alert.ThresholdValue = Threshold;
    Alert.CurrentValue = Value;
    KeQuerySystemTime(&Alert.AlertTime);

    InterlockedIncrement64(&Monitor->Stats.AlertsTriggered);

    Cb(&Alert, CbCtx);
}

//=============================================================================
// Internal: Collection DPC
//=============================================================================

static
VOID
SspmiCollectionDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++
Routine Description:
    Periodic DPC that collects system-level performance metrics.
    Runs at DISPATCH_LEVEL — only uses spin-lock-safe operations.
    Does NOT allocate paged pool, acquire push locks, or block.
--*/
{
    PSSPM_MONITOR Monitor = (PSSPM_MONITOR)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Monitor == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Monitor->Initialized, 0, 0) == 0 ||
        InterlockedCompareExchange(&Monitor->ShuttingDown, 0, 0) != 0 ||
        InterlockedCompareExchange(&Monitor->CollectionEnabled, 0, 0) == 0) {
        return;
    }

    //
    // Self-monitor: record that a collection cycle occurred.
    // Individual subsystems (memory, cache, etc.) should call
    // SsPmRecordSample from their own periodic routines. The DPC
    // here serves as the heartbeat and can record DPC-safe system
    // metrics like pool usage via MmQuerySystemMemoryInfo or
    // KeQueryActiveProcessorCountEx, but those APIs require careful
    // IRQL handling. The DPC records a collection heartbeat.
    //
    // Subsystem-specific metric collection should be wired up by
    // the caller (e.g., DriverMain registers per-subsystem collection
    // callbacks that call SsPmRecordSample).
    //
    // The DPC heartbeat ensures the timer is alive and detectable.
    //
    {
        LARGE_INTEGER Now;
        KeQuerySystemTime(&Now);

        //
        // Record a 1-event-per-tick value for EventsPerSecond tracking
        // This acts as a "I am alive" signal that can be checked by
        // the user-mode service.
        //
        SsPmRecordSample(Monitor, SsPmMetric_EventsPerSecond, 1);
    }
}
