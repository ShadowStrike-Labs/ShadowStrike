/*++
    ShadowStrike Next-Generation Antivirus
    Module: InjectionDetector.h

    Purpose: Comprehensive code injection detection for all known
             injection techniques.

    Architecture:
    - Track cross-process memory operations via operation hash table
    - Correlate operations into attack chains with sliding time window
    - Detect remote thread creation, APC injection, process hollowing
    - Per-process context tracking with reference counting
    - Asynchronous worker thread for chain analysis
    - MITRE ATT&CK T1055.xxx mapping for all detected techniques

    Lock Ordering (higher number acquired first):
        ChainLock (2) > OperationBucket.Lock (1) > CallbackLock (0)
    Never hold multiple OperationBucket locks simultaneously.
    Never call callbacks while holding any spin lock.

    IRQL Requirements:
    - All public APIs callable at IRQL <= DISPATCH_LEVEL unless noted
    - InjInitialize/InjShutdown require IRQL == PASSIVE_LEVEL
    - Callbacks are invoked at PASSIVE_LEVEL from a system worker thread

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Forward declaration for optional VAD tracker integration
//
typedef struct _VAD_TRACKER *PVAD_TRACKER;

//=============================================================================
// Pool Tags
//=============================================================================

#define INJ_POOL_TAG            'DNJI'  // Injection Detector - General
#define INJ_POOL_TAG_OP         'ONJI'  // Injection Detector - Operation
#define INJ_POOL_TAG_CHAIN      'HCJI'  // Injection Detector - Chain
#define INJ_POOL_TAG_CTX        'XCJI'  // Injection Detector - Context

//=============================================================================
// Configuration Constants
//=============================================================================

#define INJ_MAX_TRACKED_OPERATIONS      16384
#define INJ_OPERATION_TIMEOUT_MS        60000   // 1 minute correlation
#define INJ_MAX_CHAIN_OPERATIONS        32

//=============================================================================
// Operation Flags
//=============================================================================

#define INJ_FLAG_CROSS_PROCESS          0x00000001

//=============================================================================
// Chain Flags
//=============================================================================

#define INJ_CHAIN_FLAG_HAS_EXECUTE      0x00000001
#define INJ_CHAIN_FLAG_HAS_WRITE        0x00000002
#define INJ_CHAIN_FLAG_HAS_THREAD       0x00000004
#define INJ_CHAIN_FLAG_HAS_APC          0x00000008
#define INJ_CHAIN_FLAG_TRANSACTED       0x00000010

//=============================================================================
// Injection Techniques (detected by chain analysis)
//=============================================================================

typedef enum _INJ_TECHNIQUE {
    InjTechNone = 0,

    // Classic injection via remote thread
    InjTechCreateRemoteThread,          // T1055.001

    // Portable Executable injection
    InjTechPeInjection,                 // T1055.002

    // Thread context hijacking
    InjTechThreadHijacking,             // T1055.003

    // APC-based injection
    InjTechApcInjection,                // T1055.004

    // Thread Local Storage callback
    InjTechTlsCallback,                 // T1055.005

    // Extra window memory abuse
    InjTechExtraWindowMemory,           // T1055.011

    // Process hollowing (suspend + unmap + write + resume)
    InjTechProcessHollowing,            // T1055.012

    // Transacted section mapping
    InjTechProcessDoppelganging,        // T1055.013

    // Reflective DLL loading
    InjTechReflectiveDll,               // T1620

    // Atom table abuse
    InjTechAtomBombing,                 // T1055

    // NtMapViewOfSection remote mapping
    InjTechMapViewOfSection,            // T1055

    // Callback-based injection (SetWindowsHookEx, etc.)
    InjTechCallbackInjection,           // T1055

} INJ_TECHNIQUE;

//=============================================================================
// Operation Types (recorded from syscall/callback hooks)
//=============================================================================

typedef enum _INJ_OPERATION_TYPE {
    InjOpNone = 0,

    // Memory operations
    InjOpAllocate,                      // NtAllocateVirtualMemory
    InjOpWrite,                         // NtWriteVirtualMemory
    InjOpProtect,                       // NtProtectVirtualMemory
    InjOpMapSection,                    // NtMapViewOfSection

    // Thread operations
    InjOpCreateThread,                  // NtCreateThreadEx
    InjOpSetContext,                    // NtSetContextThread
    InjOpQueueApc,                      // NtQueueApcThread
    InjOpSuspend,                       // NtSuspendThread
    InjOpResume,                        // NtResumeThread

} INJ_OPERATION_TYPE;

//=============================================================================
// Injection Operation Record
//=============================================================================

typedef struct _INJ_OPERATION {
    //
    // Operation identification
    //
    INJ_OPERATION_TYPE Type;
    LARGE_INTEGER Timestamp;

    //
    // Source and target process/thread
    //
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    HANDLE SourceThreadId;
    HANDLE TargetThreadId;

    //
    // Memory details
    //
    PVOID TargetAddress;
    SIZE_T Size;
    ULONG Protection;
    PVOID SourceAddress;

    //
    // Operation flags (INJ_FLAG_*)
    //
    ULONG Flags;

    //
    // Calculated suspicion score for this individual operation
    //
    ULONG SuspicionScore;

    //
    // Hash table linkage (one entry per hash bucket)
    //
    LIST_ENTRY HashEntry;

    //
    // Chain linkage (links operation into its parent INJ_CHAIN)
    //
    LIST_ENTRY ChainEntry;

} INJ_OPERATION, *PINJ_OPERATION;

//=============================================================================
// Injection Chain — correlated sequence of operations
//=============================================================================

typedef struct _INJ_CHAIN {
    //
    // Chain identification
    //
    ULONG64 ChainId;

    //
    // Source and target process
    //
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;

    //
    // Operations in this chain
    //
    LIST_ENTRY OperationList;
    ULONG OperationCount;
    SIZE_T TotalSize;

    //
    // Timing
    //
    LARGE_INTEGER FirstOperationTime;
    LARGE_INTEGER LastOperationTime;

    //
    // Chain characteristic flags (INJ_CHAIN_FLAG_*)
    //
    ULONG Flags;

    //
    // Detection results (set after analysis)
    //
    INJ_TECHNIQUE DetectedTechnique;
    ULONG ConfidenceScore;

    //
    // Global chain list linkage
    //
    LIST_ENTRY ListEntry;

} INJ_CHAIN, *PINJ_CHAIN;

//=============================================================================
// Detection Result — output of chain analysis
//=============================================================================

#define INJ_MAX_MITRE_TECHNIQUE     16
#define INJ_MAX_MITRE_SUBTECHNIQUE  64
#define INJ_MAX_DESCRIPTION         256

typedef struct _INJ_DETECTION_RESULT {
    //
    // Detection classification
    //
    INJ_TECHNIQUE Technique;
    ULONG ConfidenceScore;              // 0-100
    ULONG Severity;                     // 1=Low, 2=Med, 3=High, 4=Critical

    //
    // Process identification
    //
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;

    //
    // Target memory region
    //
    PVOID TargetAddress;
    SIZE_T Size;

    //
    // Chain reference
    //
    ULONG64 ChainId;

    //
    // MITRE ATT&CK mapping
    //
    CHAR MitreTechnique[INJ_MAX_MITRE_TECHNIQUE];
    CHAR MitreSubTechnique[INJ_MAX_MITRE_SUBTECHNIQUE];

    //
    // Human-readable description
    //
    CHAR Description[INJ_MAX_DESCRIPTION];

    //
    // Timing
    //
    LARGE_INTEGER DetectionTime;

} INJ_DETECTION_RESULT, *PINJ_DETECTION_RESULT;

//=============================================================================
// Process Injection Context
//=============================================================================

typedef struct _INJ_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;

    //
    // Chains where this process is the target
    //
    LIST_ENTRY IncomingChains;

    //
    // Chains where this process is the source
    //
    LIST_ENTRY OutgoingChains;

    //
    // Per-context lock (protects IncomingChains, OutgoingChains)
    //
    KSPIN_LOCK Lock;

    //
    // First seen timestamp
    //
    LARGE_INTEGER FirstSeenTime;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Hash table linkage (chained — multiple contexts per bucket)
    //
    LIST_ENTRY HashEntry;

} INJ_PROCESS_CONTEXT, *PINJ_PROCESS_CONTEXT;

//=============================================================================
// Injection Detector (public portion)
//=============================================================================

typedef struct _INJ_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;

    //
    // Optional VAD tracker reference
    //
    PVAD_TRACKER VadTracker;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableRealTimeDetection;
        BOOLEAN EnableChainCorrelation;
        BOOLEAN EnableAutoBlocking;
        ULONG ChainTimeoutMs;
        ULONG MaxOperationsPerChain;
        ULONG MinConfidenceToAlert;     // 0-100
        ULONG MinConfidenceToBlock;     // 0-100
    } Config;

    //
    // Statistics (all updated via Interlocked*)
    //
    struct {
        volatile LONG64 TotalOperations;
        volatile LONG64 DetectedInjections;
        volatile LONG64 BlockedInjections;
        volatile LONG64 DroppedOperations;
        volatile LONG64 ChainsCreated;
        LARGE_INTEGER StartTime;
    } Stats;

} INJ_DETECTOR, *PINJ_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

//
// Detection notification callback.
// Called at PASSIVE_LEVEL from the analysis worker thread.
// Must not block for extended periods.
//
typedef VOID (*INJ_DETECTION_CALLBACK)(
    _In_ PINJ_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

//
// Block decision callback.
// Called at PASSIVE_LEVEL.  Return TRUE to block the injection.
//
typedef BOOLEAN (*INJ_BLOCK_CALLBACK)(
    _In_ PINJ_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Statistics snapshot (returned by InjGetStatistics)
//=============================================================================

typedef struct _INJ_STATISTICS {
    ULONG64 TotalOperations;
    ULONG64 DetectedInjections;
    ULONG64 BlockedInjections;
    ULONG64 DroppedOperations;
    ULONG64 ChainsCreated;
    ULONG64 ActiveOperations;
    ULONG64 ActiveChains;
    ULONG UptimeSeconds;
} INJ_STATISTICS, *PINJ_STATISTICS;

//=============================================================================
// Public API — Initialization (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
InjInitialize(
    _In_opt_ PVAD_TRACKER VadTracker,
    _Out_ PINJ_DETECTOR* Detector
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
InjShutdown(
    _Inout_ PINJ_DETECTOR Detector
    );

//=============================================================================
// Public API — Operation Recording (IRQL <= DISPATCH_LEVEL)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjRecordOperation(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_OPERATION_TYPE OperationType,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_opt_ HANDLE SourceThreadId,
    _In_opt_ HANDLE TargetThreadId,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _In_opt_ PVOID SourceAddress,
    _In_ ULONG Flags
    );

//=============================================================================
// Public API — Chain Analysis (IRQL <= DISPATCH_LEVEL)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjAnalyzeChain(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PINJ_DETECTION_RESULT* Result
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjDetectInjection(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T Size,
    _Out_ PINJ_DETECTION_RESULT* Result
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjGetChainInfo(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PINJ_CHAIN ChainInfo
    );

//=============================================================================
// Public API — Chain Management (IRQL <= DISPATCH_LEVEL)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjClearChain(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjClearAllChains(
    _In_ PINJ_DETECTOR Detector
    );

//=============================================================================
// Public API — Callbacks (IRQL <= DISPATCH_LEVEL)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjRegisterDetectionCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
InjUnregisterDetectionCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_DETECTION_CALLBACK Callback
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjRegisterBlockCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
InjUnregisterBlockCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_BLOCK_CALLBACK Callback
    );

//=============================================================================
// Public API — Result Lifetime (IRQL <= DISPATCH_LEVEL)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
InjFreeDetectionResult(
    _In_ PINJ_DETECTOR Detector,
    _In_ PINJ_DETECTION_RESULT Result
    );

//=============================================================================
// Public API — Statistics (IRQL <= DISPATCH_LEVEL)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
InjGetStatistics(
    _In_ PINJ_DETECTOR Detector,
    _Out_ PINJ_STATISTICS Stats
    );

//=============================================================================
// Public API — Process Lifecycle (IRQL <= DISPATCH_LEVEL)
//=============================================================================

//
// Call from PsSetCreateProcessNotifyRoutineEx callback when Create==FALSE.
// Cleans up the process context for the exiting process.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
InjNotifyProcessExit(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

#ifdef __cplusplus
}
#endif
