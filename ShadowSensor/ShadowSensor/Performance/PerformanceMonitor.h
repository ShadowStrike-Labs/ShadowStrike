/*++
    ShadowStrike Next-Generation Antivirus
    Module: PerformanceMonitor.h - Kernel driver performance monitoring
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define PM_POOL_TAG 'NOMP'

typedef enum _PM_METRIC_TYPE {
    PmMetric_CallbackLatency = 0,
    PmMetric_MemoryUsage,
    PmMetric_PoolUsage,
    PmMetric_LookasideHits,
    PmMetric_LookasideMisses,
    PmMetric_CacheHitRate,
    PmMetric_EventsPerSecond,
    PmMetric_DroppedEvents,
    PmMetric_CPUUsage,
    PmMetric_IOOperations,
} PM_METRIC_TYPE;

typedef struct _PM_METRIC_SAMPLE {
    PM_METRIC_TYPE Type;
    LARGE_INTEGER Timestamp;
    
    union {
        ULONG64 Counter;
        DOUBLE Percentage;
        struct {
            ULONG64 Value;
            ULONG64 Max;
        } Bounded;
    } Value;
    
    LIST_ENTRY ListEntry;
} PM_METRIC_SAMPLE, *PPM_METRIC_SAMPLE;

typedef struct _PM_METRIC_STATS {
    PM_METRIC_TYPE Type;
    
    ULONG64 SampleCount;
    DOUBLE Mean;
    DOUBLE Min;
    DOUBLE Max;
    DOUBLE StandardDeviation;
    DOUBLE Percentile95;
    DOUBLE Percentile99;
    
    LARGE_INTEGER LastSampleTime;
} PM_METRIC_STATS, *PPM_METRIC_STATS;

typedef struct _PM_THRESHOLD_ALERT {
    PM_METRIC_TYPE Metric;
    DOUBLE ThresholdValue;
    DOUBLE CurrentValue;
    BOOLEAN IsExceeded;
    LARGE_INTEGER AlertTime;
    LIST_ENTRY ListEntry;
} PM_THRESHOLD_ALERT, *PPM_THRESHOLD_ALERT;

typedef VOID (*PM_ALERT_CALLBACK)(
    _In_ PPM_THRESHOLD_ALERT Alert,
    _In_opt_ PVOID Context
);

typedef struct _PM_MONITOR {
    BOOLEAN Initialized;
    
    // Sample storage (ring buffer per metric)
    struct {
        PPM_METRIC_SAMPLE Samples;
        ULONG Capacity;
        ULONG Head;
        ULONG Count;
        KSPIN_LOCK Lock;
    } MetricBuffers[16];
    
    // Thresholds
    LIST_ENTRY ThresholdList;
    EX_PUSH_LOCK ThresholdLock;
    
    // Callback
    PM_ALERT_CALLBACK AlertCallback;
    PVOID AlertContext;
    
    // Periodic collection
    KTIMER CollectionTimer;
    KDPC CollectionDpc;
    ULONG CollectionIntervalMs;
    BOOLEAN CollectionEnabled;
    
    struct {
        volatile LONG64 SamplesCollected;
        volatile LONG64 AlertsTriggered;
        LARGE_INTEGER StartTime;
    } Stats;
} PM_MONITOR, *PPM_MONITOR;

NTSTATUS PmInitialize(_Out_ PPM_MONITOR* Monitor);
VOID PmShutdown(_Inout_ PPM_MONITOR Monitor);
NTSTATUS PmRecordSample(_In_ PPM_MONITOR Monitor, _In_ PM_METRIC_TYPE Metric, _In_ ULONG64 Value);
NTSTATUS PmRecordPercentage(_In_ PPM_MONITOR Monitor, _In_ PM_METRIC_TYPE Metric, _In_ DOUBLE Percentage);
NTSTATUS PmGetStats(_In_ PPM_MONITOR Monitor, _In_ PM_METRIC_TYPE Metric, _Out_ PPM_METRIC_STATS Stats);
NTSTATUS PmSetThreshold(_In_ PPM_MONITOR Monitor, _In_ PM_METRIC_TYPE Metric, _In_ DOUBLE Threshold);
NTSTATUS PmRegisterAlertCallback(_In_ PPM_MONITOR Monitor, _In_ PM_ALERT_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS PmEnableCollection(_In_ PPM_MONITOR Monitor, _In_ ULONG IntervalMs);
NTSTATUS PmDisableCollection(_In_ PPM_MONITOR Monitor);

#ifdef __cplusplus
}
#endif
