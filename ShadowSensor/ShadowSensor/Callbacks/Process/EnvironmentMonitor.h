/*++
    ShadowStrike Next-Generation Antivirus
    Module: EnvironmentMonitor.h - Environment variable tracking
    Copyright (c) ShadowStrike Team

    SECURITY HARDENED v3.0.0:
    - Proper EX_PUSH_LOCK synchronization (no spinlock confusion)
    - Reference counting for safe lifetime management
    - ProcessId epoch validation for cache safety
    - All string operations bounded
    - IRQL-safe design throughout
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags for memory tracking
//
#define EM_POOL_TAG         'NOME'
#define EM_ENV_VAR_TAG      'VENE'
#define EM_PATH_TAG         'PTNE'
#define EM_STRING_TAG       'STNE'

//
// Size limits - carefully chosen to prevent stack overflow and DoS
//
#define EM_MAX_ENV_NAME         256
#define EM_MAX_ENV_VALUE        8192    // Reduced from 32KB to prevent excessive allocations
#define EM_MAX_ENV_BLOCK_SIZE   (64 * 1024)
#define EM_MAX_VARIABLES        1024
#define EM_MAX_PATH_ENTRIES     256
#define EM_MAX_CACHE_ENTRIES    2048

//
// Iteration safety limits
//
#define EM_MAX_LIST_ITERATIONS  65536

//
// Suspicion flags for environment analysis
//
typedef enum _EM_SUSPICION {
    EmSuspicion_None                = 0x00000000,
    EmSuspicion_ModifiedPath        = 0x00000001,
    EmSuspicion_DLLSearchOrder      = 0x00000002,
    EmSuspicion_ProxySettings       = 0x00000004,
    EmSuspicion_TempOverride        = 0x00000008,
    EmSuspicion_HiddenVariable      = 0x00000010,
    EmSuspicion_EncodedValue        = 0x00000020,
} EM_SUSPICION;

//
// Allocation source tracking to prevent allocator mismatch
//
typedef enum _EM_ALLOC_SOURCE {
    EmAllocSource_Pool = 0,
    EmAllocSource_Lookaside = 1
} EM_ALLOC_SOURCE;

//
// Environment variable entry with allocation tracking
//
typedef struct _EM_ENV_VARIABLE {
    //
    // Magic for structure validation
    //
    ULONG Magic;

    //
    // Allocation source for proper cleanup
    //
    EM_ALLOC_SOURCE AllocSource;

    //
    // Variable data with bounded sizes
    //
    CHAR Name[EM_MAX_ENV_NAME];
    CHAR Value[EM_MAX_ENV_VALUE];
    USHORT NameLength;
    USHORT ValueLength;

    //
    // Metadata
    //
    LARGE_INTEGER LastModified;
    BOOLEAN IsSystemVariable;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
} EM_ENV_VARIABLE, *PEM_ENV_VARIABLE;

#define EM_ENV_VAR_MAGIC    0x56454E56  // 'VENV'

//
// Process environment container with proper synchronization
//
typedef struct _EM_PROCESS_ENV {
    //
    // Magic for structure validation
    //
    ULONG Magic;

    //
    // Process identification with epoch for reuse detection
    //
    HANDLE ProcessId;
    LARGE_INTEGER ProcessCreateTime;    // Epoch for ProcessId reuse detection

    //
    // Variable list with EX_PUSH_LOCK (NOT spinlock!)
    // EX_PUSH_LOCK allows shared/exclusive access at PASSIVE_LEVEL
    //
    LIST_ENTRY VariableList;
    EX_PUSH_LOCK VariableLock;
    ULONG VariableCount;

    //
    // Reference counting for safe lifetime
    //
    volatile LONG ReferenceCount;

    //
    // Linked state tracking (safer than IsListEmpty on entry)
    //
    BOOLEAN IsLinkedToCache;

    //
    // Analysis results
    //
    EM_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    BOOLEAN AnalysisComplete;

    //
    // Cache linkage
    //
    LIST_ENTRY CacheListEntry;
    LARGE_INTEGER CacheTime;

    //
    // Back reference to owning monitor
    //
    struct _EM_MONITOR* OwnerMonitor;
} EM_PROCESS_ENV, *PEM_PROCESS_ENV;

#define EM_PROCESS_ENV_MAGIC    0x50454E56  // 'PENV'

//
// Monitor context with proper synchronization
//
typedef struct _EM_MONITOR {
    //
    // Magic for structure validation
    //
    ULONG Magic;

    //
    // Initialization and shutdown state
    //
    BOOLEAN Initialized;
    volatile LONG ShuttingDown;

    //
    // Process environment cache
    //
    LIST_ENTRY ProcessCacheList;
    EX_PUSH_LOCK CacheLock;
    volatile LONG CacheCount;

    //
    // Reference counting for safe shutdown
    //
    volatile LONG ReferenceCount;
    KEVENT ShutdownCompleteEvent;

    //
    // Lookaside list for environment variable allocations
    //
    NPAGED_LOOKASIDE_LIST EnvVarLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Statistics
    //
    struct {
        volatile LONG64 ProcessesMonitored;
        volatile LONG64 SuspiciousEnvFound;
        volatile LONG64 CacheHits;
        volatile LONG64 CacheMisses;
        LARGE_INTEGER StartTime;
    } Stats;
} EM_MONITOR, *PEM_MONITOR;

#define EM_MONITOR_MAGIC    0x454E564D  // 'ENVM'

//
// Public API - All functions require PASSIVE_LEVEL
//

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmInitialize(
    _Out_ PEM_MONITOR* Monitor
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EmShutdown(
    _Inout_ PEM_MONITOR Monitor
);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmCaptureEnvironment(
    _In_ PEM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PEM_PROCESS_ENV* Env
);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmAnalyzeEnvironment(
    _In_ PEM_MONITOR Monitor,
    _In_ PEM_PROCESS_ENV Env,
    _Out_ PEM_SUSPICION* Flags
);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmGetVariable(
    _In_ PEM_PROCESS_ENV Env,
    _In_ PCSTR Name,
    _In_ SIZE_T NameMaxLength,
    _Out_ PEM_ENV_VARIABLE* Variable
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EmReleaseEnvironment(
    _In_ PEM_PROCESS_ENV Env
);

//
// Reference counting helpers for external callers
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EmAcquireEnvironmentReference(
    _In_ PEM_PROCESS_ENV Env
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EmReleaseEnvironmentReference(
    _In_ PEM_PROCESS_ENV Env
);

#ifdef __cplusplus
}
#endif
