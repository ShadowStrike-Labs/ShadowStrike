/*++
    ShadowStrike Next-Generation Antivirus
    Module: HeapSpray.h
    
    Purpose: Heap spray attack detection through pattern analysis
             and memory allocation monitoring.
             
    Architecture:
    - Track heap allocations for spray patterns
    - Detect NOP sled sprays
    - Identify JIT spray patterns
    - Monitor allocation frequency anomalies
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/MemoryTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define HS_POOL_TAG_CONTEXT     'CXSH'  // Heap Spray - Context
#define HS_POOL_TAG_PATTERN     'TPSH'  // Heap Spray - Pattern
#define HS_POOL_TAG_ALLOC       'LASH'  // Heap Spray - Allocation

//=============================================================================
// Configuration Constants
//=============================================================================

#define HS_MIN_SPRAY_SIZE               (1024 * 1024)       // 1 MB
#define HS_MAX_TRACKED_ALLOCATIONS      65536
#define HS_ALLOCATION_WINDOW_MS         5000                // 5 second window
#define HS_MIN_SIMILAR_ALLOCATIONS      100                 // Trigger threshold
#define HS_PATTERN_SAMPLE_SIZE          256                 // Bytes to sample

//=============================================================================
// Spray Types
//=============================================================================

typedef enum _HS_SPRAY_TYPE {
    HsSprayType_Unknown = 0,
    HsSprayType_NopSled,                // Classic NOP spray
    HsSprayType_HeapFeng,               // Heap feng shui
    HsSprayType_JitSpray,               // JIT compiled spray
    HsSprayType_ArraySpray,             // JavaScript array spray
    HsSprayType_StringSpray,            // String-based spray
    HsSprayType_TypedArraySpray,        // TypedArray spray
    HsSprayType_ObjectSpray,            // Object spray
    HsSprayType_WasmSpray,              // WebAssembly spray
} HS_SPRAY_TYPE;

//=============================================================================
// Detection Flags
//=============================================================================

typedef enum _HS_DETECTION_FLAGS {
    HsFlag_None                     = 0x00000000,
    HsFlag_HighAllocationRate       = 0x00000001,
    HsFlag_RepeatedPattern          = 0x00000002,
    HsFlag_SuspiciousSize           = 0x00000004,
    HsFlag_ExecutableAlloc          = 0x00000008,
    HsFlag_AlignedAddresses         = 0x00000010,
    HsFlag_LargeContiguous          = 0x00000020,
    HsFlag_ShellcodePattern         = 0x00000040,
    HsFlag_JitPattern               = 0x00000080,
} HS_DETECTION_FLAGS;

//=============================================================================
// Allocation Record
//=============================================================================

typedef struct _HS_ALLOCATION_RECORD {
    //
    // Allocation details
    //
    PVOID Address;
    SIZE_T Size;
    ULONG Protection;
    LARGE_INTEGER Timestamp;
    
    //
    // Pattern analysis
    //
    UCHAR PatternSample[HS_PATTERN_SAMPLE_SIZE];
    ULONG PatternHash;
    ULONG RepetitionScore;              // How repetitive the content is
    
    //
    // Source
    //
    PVOID ReturnAddress;
    HANDLE ThreadId;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} HS_ALLOCATION_RECORD, *PHS_ALLOCATION_RECORD;

//=============================================================================
// Spray Detection Result
//=============================================================================

typedef struct _HS_SPRAY_RESULT {
    //
    // Detection summary
    //
    BOOLEAN SprayDetected;
    HS_SPRAY_TYPE Type;
    HS_DETECTION_FLAGS Flags;
    ULONG ConfidenceScore;
    
    //
    // Process context
    //
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    
    //
    // Spray metrics
    //
    ULONG AllocationCount;
    SIZE_T TotalSize;
    SIZE_T AverageSize;
    ULONG AllocationsPerSecond;
    
    //
    // Pattern information
    //
    UCHAR DominantPattern[64];
    ULONG DominantPatternSize;
    ULONG PatternRepetitions;
    ULONG UniquePatterns;
    
    //
    // Address distribution
    //
    PVOID LowestAddress;
    PVOID HighestAddress;
    SIZE_T AddressSpan;
    ULONG AlignedCount;                 // Count of page-aligned
    
    //
    // Timing
    //
    LARGE_INTEGER FirstAllocation;
    LARGE_INTEGER LastAllocation;
    ULONG DurationMs;
    
} HS_SPRAY_RESULT, *PHS_SPRAY_RESULT;

//=============================================================================
// Process Spray Context
//=============================================================================

typedef struct _HS_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    PEPROCESS Process;
    
    //
    // Allocation tracking
    //
    LIST_ENTRY AllocationList;
    KSPIN_LOCK AllocationLock;
    volatile LONG AllocationCount;
    
    //
    // Pattern hash table
    //
    LIST_ENTRY PatternBuckets[256];
    volatile LONG UniquePatterns;
    
    //
    // Spray metrics
    //
    SIZE_T TotalAllocatedSize;
    ULONG AllocationsInWindow;
    LARGE_INTEGER WindowStartTime;
    
    //
    // Spray state
    //
    BOOLEAN SprayInProgress;
    HS_SPRAY_TYPE SuspectedType;
    ULONG SprayScore;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} HS_PROCESS_CONTEXT, *PHS_PROCESS_CONTEXT;

//=============================================================================
// Heap Spray Detector
//=============================================================================

typedef struct _HS_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Process tracking
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;
    
    //
    // Global allocation pool
    //
    struct {
        LIST_ENTRY FreeList;
        KSPIN_LOCK Lock;
        volatile LONG FreeCount;
        PHS_ALLOCATION_RECORD PoolMemory;
        ULONG PoolSize;
    } AllocationPool;
    
    //
    // Configuration
    //
    struct {
        SIZE_T MinSpraySizeBytes;
        ULONG MinAllocationCount;
        ULONG AllocationWindowMs;
        ULONG PatternSampleSize;
        BOOLEAN TrackAllProcesses;
    } Config;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalAllocationsTracked;
        volatile LONG64 SpraysDetected;
        volatile LONG64 ProcessesMonitored;
        LARGE_INTEGER StartTime;
    } Stats;
    
} HS_DETECTOR, *PHS_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*HS_SPRAY_CALLBACK)(
    _In_ PHS_SPRAY_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
HsInitialize(
    _Out_ PHS_DETECTOR* Detector
    );

VOID
HsShutdown(
    _Inout_ PHS_DETECTOR Detector
    );

//=============================================================================
// Public API - Process Tracking
//=============================================================================

NTSTATUS
HsStartTracking(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

NTSTATUS
HsStopTracking(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

//=============================================================================
// Public API - Allocation Monitoring
//=============================================================================

NTSTATUS
HsRecordAllocation(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _In_opt_ PVOID ReturnAddress
    );

NTSTATUS
HsRecordDeallocation(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    );

//=============================================================================
// Public API - Detection
//=============================================================================

NTSTATUS
HsAnalyzeProcess(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PHS_SPRAY_RESULT* Result
    );

NTSTATUS
HsCheckForSpray(
    _In_ PHS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN SprayDetected,
    _Out_opt_ PHS_SPRAY_TYPE Type,
    _Out_opt_ PULONG Score
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
HsRegisterCallback(
    _In_ PHS_DETECTOR Detector,
    _In_ HS_SPRAY_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
HsUnregisterCallback(
    _In_ PHS_DETECTOR Detector,
    _In_ HS_SPRAY_CALLBACK Callback
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
HsFreeResult(
    _In_ PHS_SPRAY_RESULT Result
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _HS_STATISTICS {
    ULONG TrackedProcesses;
    ULONG64 TotalAllocations;
    ULONG64 SpraysDetected;
    LARGE_INTEGER UpTime;
} HS_STATISTICS, *PHS_STATISTICS;

NTSTATUS
HsGetStatistics(
    _In_ PHS_DETECTOR Detector,
    _Out_ PHS_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
