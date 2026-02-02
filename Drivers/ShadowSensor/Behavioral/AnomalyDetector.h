/*++
    ShadowStrike Next-Generation Antivirus
    Module: AnomalyDetector.h - Behavioral anomaly detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define AD_POOL_TAG 'DADA'
#define AD_BASELINE_SAMPLES 1000

typedef enum _AD_METRIC_TYPE {
    AdMetric_CPUUsage = 0,
    AdMetric_MemoryUsage,
    AdMetric_FileOperations,
    AdMetric_NetworkConnections,
    AdMetric_RegistryOperations,
    AdMetric_ProcessCreation,
    AdMetric_ThreadCreation,
    AdMetric_DLLLoads,
    AdMetric_HandleCount,
    AdMetric_PrivilegeUse,
    AdMetric_Custom,
} AD_METRIC_TYPE;

typedef struct _AD_BASELINE {
    AD_METRIC_TYPE Type;
    
    // Statistical baseline
    DOUBLE Mean;
    DOUBLE StandardDeviation;
    DOUBLE Min;
    DOUBLE Max;
    ULONG SampleCount;
    
    // Recent samples for sliding window
    DOUBLE Samples[AD_BASELINE_SAMPLES];
    ULONG CurrentIndex;
    BOOLEAN IsFull;
    
    LARGE_INTEGER LastUpdated;
    LIST_ENTRY ListEntry;
} AD_BASELINE, *PAD_BASELINE;

typedef struct _AD_ANOMALY {
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    AD_METRIC_TYPE MetricType;
    
    // Detected anomaly
    DOUBLE ObservedValue;
    DOUBLE ExpectedValue;
    DOUBLE DeviationSigmas;             // Number of standard deviations
    
    ULONG SeverityScore;                // 0-100
    BOOLEAN IsHighConfidence;
    
    LARGE_INTEGER DetectionTime;
    LIST_ENTRY ListEntry;
} AD_ANOMALY, *PAD_ANOMALY;

typedef VOID (*AD_ANOMALY_CALLBACK)(
    _In_ PAD_ANOMALY Anomaly,
    _In_opt_ PVOID Context
);

typedef struct _AD_DETECTOR {
    BOOLEAN Initialized;
    
    // Global baselines
    LIST_ENTRY GlobalBaselines;
    EX_PUSH_LOCK GlobalBaselineLock;
    
    // Per-process baselines
    LIST_ENTRY ProcessBaselines;
    EX_PUSH_LOCK ProcessBaselineLock;
    
    // Configuration
    DOUBLE SigmaThreshold;              // Default 3.0 (3 sigma rule)
    ULONG MinimumSamples;               // Minimum samples before detection
    
    // Anomalies
    LIST_ENTRY AnomalyList;
    KSPIN_LOCK AnomalyLock;
    volatile LONG AnomalyCount;
    
    // Callback
    AD_ANOMALY_CALLBACK Callback;
    PVOID CallbackContext;
    
    struct {
        volatile LONG64 SamplesProcessed;
        volatile LONG64 AnomaliesDetected;
        LARGE_INTEGER StartTime;
    } Stats;
} AD_DETECTOR, *PAD_DETECTOR;

NTSTATUS AdInitialize(_Out_ PAD_DETECTOR* Detector);
VOID AdShutdown(_Inout_ PAD_DETECTOR Detector);
NTSTATUS AdSetThreshold(_In_ PAD_DETECTOR Detector, _In_ DOUBLE SigmaThreshold);
NTSTATUS AdRegisterCallback(_In_ PAD_DETECTOR Detector, _In_ AD_ANOMALY_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS AdRecordSample(_In_ PAD_DETECTOR Detector, _In_opt_ HANDLE ProcessId, _In_ AD_METRIC_TYPE Metric, _In_ DOUBLE Value);
NTSTATUS AdCheckForAnomaly(_In_ PAD_DETECTOR Detector, _In_opt_ HANDLE ProcessId, _In_ AD_METRIC_TYPE Metric, _In_ DOUBLE Value, _Out_ PBOOLEAN IsAnomaly, _Out_opt_ PAD_ANOMALY* Anomaly);
NTSTATUS AdGetBaseline(_In_ PAD_DETECTOR Detector, _In_opt_ HANDLE ProcessId, _In_ AD_METRIC_TYPE Metric, _Out_ PAD_BASELINE* Baseline);
NTSTATUS AdGetRecentAnomalies(_In_ PAD_DETECTOR Detector, _In_ ULONG MaxAgeSeconds, _Out_writes_to_(Max, *Count) PAD_ANOMALY* Anomalies, _In_ ULONG Max, _Out_ PULONG Count);
VOID AdFreeAnomaly(_In_ PAD_ANOMALY Anomaly);

#ifdef __cplusplus
}
#endif
