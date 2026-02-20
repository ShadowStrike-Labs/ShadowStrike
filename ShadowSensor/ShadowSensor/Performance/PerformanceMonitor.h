/*++
    ShadowStrike Next-Generation Antivirus
    Module: PerformanceMonitor.h - Kernel driver performance monitoring

    Purpose: Self-monitoring subsystem that tracks driver performance metrics
    (callback latencies, memory usage, cache efficiency, event throughput)
    to detect degradation and enforce resource budgets.

    Naming: All public symbols use the SsPm prefix (ShadowStrike Performance Monitor)
    to avoid collision with the PrivilegeMonitor PM_ namespace in this codebase.

    IRQL Contracts:
    - SsPmInitialize:           PASSIVE_LEVEL only
    - SsPmShutdown:             PASSIVE_LEVEL only
    - SsPmRecordSample:         <= DISPATCH_LEVEL (spin-lock safe)
    - SsPmRecordLatency:        <= DISPATCH_LEVEL
    - SsPmGetStats:             <= APC_LEVEL (PASSIVE preferred)
    - SsPmSetThreshold:         <= APC_LEVEL
    - SsPmRegisterAlertCallback:<= APC_LEVEL
    - SsPmEnableCollection:     PASSIVE_LEVEL only
    - SsPmDisableCollection:    PASSIVE_LEVEL only
    - Alert callbacks:          Invoked at DISPATCH_LEVEL (from DPC context)

    All statistics are integer-based (no floating point in kernel).
    Percentages are stored as parts-per-10000 (basis points) for precision
    without FP. Latencies are in 100ns ticks (KeQueryPerformanceCounter units
    converted to QPC ticks).

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define SSPM_POOL_TAG         'mPsS'   // SsP m(onitor)
#define SSPM_POOL_TAG_SAMPLE  'sPsS'   // SsP s(ample)

//=============================================================================
// Metric Types
//=============================================================================

typedef enum _SSPM_METRIC_TYPE {
    SsPmMetric_CallbackLatencyUs = 0,   // Callback latency in microseconds
    SsPmMetric_MemoryBytes,             // Total memory usage in bytes
    SsPmMetric_PoolBytes,               // Pool allocation bytes
    SsPmMetric_LookasideHits,           // Lookaside list hits (counter)
    SsPmMetric_LookasideMisses,         // Lookaside list misses (counter)
    SsPmMetric_CacheHitRateBps,         // Cache hit rate in basis points (0-10000)
    SsPmMetric_EventsPerSecond,         // Event throughput
    SsPmMetric_DroppedEvents,           // Dropped event counter
    SsPmMetric_CpuTimeBps,             // CPU time in basis points (0-10000)
    SsPmMetric_IOOperations,            // I/O operation counter
    SsPmMetric_Count                    // Sentinel — MUST be last
} SSPM_METRIC_TYPE;

//
// Compile-time check: ensure metric count fits in buffer array
//
C_ASSERT(SsPmMetric_Count <= 16);

//=============================================================================
// Ring Buffer Sample (no floating point, no LIST_ENTRY)
//=============================================================================

typedef struct _SSPM_SAMPLE {
    LARGE_INTEGER Timestamp;
    ULONG64 Value;              // Raw metric value (units depend on metric type)
} SSPM_SAMPLE, *PSSPM_SAMPLE;

//=============================================================================
// Statistics (integer-only, no floating point)
//=============================================================================

typedef struct _SSPM_METRIC_STATS {
    SSPM_METRIC_TYPE Type;
    ULONG64 SampleCount;
    ULONG64 Mean;               // Average value
    ULONG64 Min;
    ULONG64 Max;
    ULONG64 Percentile95;
    ULONG64 Percentile99;
    LARGE_INTEGER OldestSampleTime;
    LARGE_INTEGER NewestSampleTime;
} SSPM_METRIC_STATS, *PSSPM_METRIC_STATS;

//=============================================================================
// Threshold Alert
//=============================================================================

typedef struct _SSPM_THRESHOLD_ALERT {
    SSPM_METRIC_TYPE Metric;
    ULONG64 ThresholdValue;     // Alert if metric exceeds this
    ULONG64 CurrentValue;       // Value that triggered the alert
    LARGE_INTEGER AlertTime;
} SSPM_THRESHOLD_ALERT, *PSSPM_THRESHOLD_ALERT;

//
// Alert callback — invoked at DISPATCH_LEVEL from DPC context.
// Implementations MUST NOT block, allocate paged pool, or lower IRQL.
//
typedef VOID (*SSPM_ALERT_CALLBACK)(
    _In_ PSSPM_THRESHOLD_ALERT Alert,
    _In_opt_ PVOID Context
);

//=============================================================================
// Monitor Handle (opaque to callers; internals in .c file)
//=============================================================================

typedef struct _SSPM_MONITOR SSPM_MONITOR, *PSSPM_MONITOR;

//=============================================================================
// Public API
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SsPmInitialize(
    _Out_ PSSPM_MONITOR* Monitor
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
SsPmShutdown(
    _Inout_ PSSPM_MONITOR Monitor
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SsPmRecordSample(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ ULONG64 Value
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SsPmRecordLatency(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ LARGE_INTEGER StartTick
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SsPmGetStats(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _Out_ PSSPM_METRIC_STATS Stats
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SsPmSetThreshold(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_METRIC_TYPE Metric,
    _In_ ULONG64 ThresholdValue
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SsPmRegisterAlertCallback(
    _In_ PSSPM_MONITOR Monitor,
    _In_ SSPM_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SsPmEnableCollection(
    _In_ PSSPM_MONITOR Monitor,
    _In_ ULONG IntervalMs
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SsPmDisableCollection(
    _In_ PSSPM_MONITOR Monitor
    );

#ifdef __cplusplus
}
#endif
