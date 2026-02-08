/*++
    ShadowStrike Next-Generation Antivirus
    Module: AnomalyDetector.h - Behavioral anomaly detection
    Copyright (c) ShadowStrike Team

    ENTERPRISE-GRADE IMPLEMENTATION

    This header defines the public API for statistical anomaly detection.
    All structures use opaque handles to maintain ABI stability.

    IRQL REQUIREMENTS:
    - All public APIs require IRQL <= APC_LEVEL unless otherwise noted
    - Callback functions are invoked at PASSIVE_LEVEL

    THREAD SAFETY:
    - All public APIs are thread-safe
    - Callbacks may be invoked concurrently
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tag for all allocations
//
#define AD_POOL_TAG 'DADA'

//
// Version for compatibility checking
//
#define AD_VERSION_MAJOR    2
#define AD_VERSION_MINOR    1
#define AD_VERSION          ((AD_VERSION_MAJOR << 16) | AD_VERSION_MINOR)

//
// Configuration limits
//
#define AD_BASELINE_SAMPLES         1000
#define AD_MAX_PROCESS_NAME_CCH     260

//
// Metric types for anomaly detection
//
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
    AdMetric_MaxValue = AdMetric_Custom
} AD_METRIC_TYPE;

//
// Compile-time validation of metric array bounds
//
C_ASSERT(AdMetric_MaxValue == AdMetric_Custom);
#define AD_METRIC_COUNT (AdMetric_MaxValue + 1)

//
// Baseline statistics (read-only snapshot for callers)
//
typedef struct _AD_BASELINE_INFO {
    AD_METRIC_TYPE Type;
    DOUBLE Mean;
    DOUBLE StandardDeviation;
    DOUBLE Min;
    DOUBLE Max;
    ULONG SampleCount;
    BOOLEAN IsFull;
    LARGE_INTEGER LastUpdated;
} AD_BASELINE_INFO, *PAD_BASELINE_INFO;

//
// Anomaly record (caller-owned copy)
//
typedef struct _AD_ANOMALY_INFO {
    HANDLE ProcessId;
    WCHAR ProcessName[AD_MAX_PROCESS_NAME_CCH];
    AD_METRIC_TYPE MetricType;

    DOUBLE ObservedValue;
    DOUBLE ExpectedValue;
    DOUBLE DeviationSigmas;

    ULONG SeverityScore;        // 0-100
    BOOLEAN IsHighConfidence;

    LARGE_INTEGER DetectionTime;
} AD_ANOMALY_INFO, *PAD_ANOMALY_INFO;

//
// Opaque detector handle
//
typedef struct _AD_DETECTOR *PAD_DETECTOR;

//
// Callback function type
// IRQL: Called at PASSIVE_LEVEL
// Thread safety: May be called concurrently from multiple threads
//
typedef VOID
(NTAPI *AD_ANOMALY_CALLBACK)(
    _In_ CONST AD_ANOMALY_INFO* AnomalyInfo,
    _In_opt_ PVOID Context
    );

//
// Callback handle for unregistration
//
typedef PVOID AD_CALLBACK_HANDLE;

// ============================================================================
// PUBLIC API
// ============================================================================

//
// Initialize the anomaly detector
// IRQL: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AdInitialize(
    _Out_ PAD_DETECTOR* Detector
    );

//
// Shutdown and free the anomaly detector
// IRQL: PASSIVE_LEVEL
// Note: Blocks until all operations complete
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AdShutdown(
    _Inout_ PAD_DETECTOR Detector
    );

//
// Set the detection threshold (sigma value)
// IRQL: <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdSetThreshold(
    _In_ PAD_DETECTOR Detector,
    _In_ DOUBLE SigmaThreshold
    );

//
// Register a callback for anomaly notifications
// IRQL: <= APC_LEVEL
// Returns: Callback handle for use with AdUnregisterCallback
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdRegisterCallback(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_ANOMALY_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ AD_CALLBACK_HANDLE* Handle
    );

//
// Unregister a previously registered callback
// IRQL: <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdUnregisterCallback(
    _In_ PAD_DETECTOR Detector,
    _In_ AD_CALLBACK_HANDLE Handle
    );

//
// Record a sample for baseline building
// IRQL: <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdRecordSample(
    _In_ PAD_DETECTOR Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value
    );

//
// Check if a value is anomalous
// IRQL: <= APC_LEVEL
// Note: Also records the sample if not anomalous
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdCheckForAnomaly(
    _In_ PAD_DETECTOR Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _In_ DOUBLE Value,
    _Out_ PBOOLEAN IsAnomaly,
    _Out_opt_ PAD_ANOMALY_INFO AnomalyInfo
    );

//
// Get baseline information for a metric
// IRQL: <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdGetBaseline(
    _In_ PAD_DETECTOR Detector,
    _In_opt_ HANDLE ProcessId,
    _In_ AD_METRIC_TYPE Metric,
    _Out_ PAD_BASELINE_INFO BaselineInfo
    );

//
// Get recent anomalies
// IRQL: <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdGetRecentAnomalies(
    _In_ PAD_DETECTOR Detector,
    _In_ ULONG MaxAgeSeconds,
    _Out_writes_to_(MaxCount, *ActualCount) PAD_ANOMALY_INFO AnomalyArray,
    _In_ ULONG MaxCount,
    _Out_ PULONG ActualCount
    );

//
// Get detector statistics
//
typedef struct _AD_STATISTICS {
    LONG64 SamplesProcessed;
    LONG64 AnomaliesDetected;
    LONG ProcessBaselineCount;
    LONG AnomalyCount;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER Uptime;
} AD_STATISTICS, *PAD_STATISTICS;

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
AdGetStatistics(
    _In_ PAD_DETECTOR Detector,
    _Out_ PAD_STATISTICS Statistics
    );

#ifdef __cplusplus
}
#endif
