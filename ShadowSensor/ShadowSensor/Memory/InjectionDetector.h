/*++
    ShadowStrike Next-Generation Antivirus
    Module: InjectionDetector.h
    
    Purpose: Comprehensive code injection detection for all known
             injection techniques.
             
    Architecture:
    - Track cross-process memory operations
    - Detect remote thread creation
    - Monitor APC queuing
    - Identify DLL injection variants
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/MemoryTypes.h"
#include "../../Shared/BehaviorTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define INJ_POOL_TAG_CONTEXT    'CXJI'  // Injection Detector - Context
#define INJ_POOL_TAG_EVENT      'EVJI'  // Injection Detector - Event
#define INJ_POOL_TAG_CHAIN      'HCJI'  // Injection Detector - Chain

//=============================================================================
// Configuration Constants
//=============================================================================

#define INJ_MAX_TRACKED_OPERATIONS      16384
#define INJ_OPERATION_TIMEOUT_MS        60000   // 1 minute correlation
#define INJ_MAX_CHAIN_OPERATIONS        32

//=============================================================================
// Injection Techniques
//=============================================================================

typedef enum _INJ_TECHNIQUE {
    InjTechnique_Unknown = 0,
    
    // Classic DLL Injection
    InjTechnique_CreateRemoteThread,        // CreateRemoteThread + LoadLibrary
    InjTechnique_NtCreateThreadEx,          // NtCreateThreadEx variant
    InjTechnique_RtlCreateUserThread,       // RtlCreateUserThread variant
    
    // APC Injection
    InjTechnique_APCQueue,                  // QueueUserAPC
    InjTechnique_EarlyBirdAPC,              // APC before main thread runs
    
    // Code Injection
    InjTechnique_WriteProcessMemory,        // Direct memory write
    InjTechnique_MappedInjection,           // Shared section mapping
    InjTechnique_SetThreadContext,          // Thread hijacking
    
    // Advanced Techniques
    InjTechnique_AtomBombing,               // Atom table injection
    InjTechnique_ProcessHollowing,          // Process hollowing
    InjTechnique_ProcessDoppelganging,      // Transacted section
    InjTechnique_Ghosting,                  // Delete-pending injection
    InjTechnique_Herpaderping,              // Modified file injection
    
    // Module Injection
    InjTechnique_ReflectiveDLL,             // Reflective DLL loading
    InjTechnique_ModuleStomping,            // Module stomping
    InjTechnique_PhantomDLL,                // Phantom DLL hollowing
    
    // Callback Injection
    InjTechnique_WindowsHook,               // SetWindowsHookEx
    InjTechnique_AppInit,                   // AppInit_DLLs
    InjTechnique_ShimInjection,             // Application shims
    
    // Memory Manipulation
    InjTechnique_MapViewRemote,             // NtMapViewOfSection remote
    InjTechnique_SectionCreation,           // Suspicious section use
    
    // Thread Manipulation
    InjTechnique_ThreadExecution,           // NtSetContextThread hijack
    InjTechnique_FiberLocal,                // Fiber local storage
    InjTechnique_ThreadPoolCallback,        // Thread pool abuse
    
    // Misc
    InjTechnique_ExtraWindowMemory,         // Extra window bytes
    InjTechnique_PropagateCallback,         // EM_GETHANDLE/CB_FINDSTRING
    InjTechnique_ServiceShell,              // Service control injection
    
} INJ_TECHNIQUE;

//=============================================================================
// Operation Types
//=============================================================================

typedef enum _INJ_OPERATION_TYPE {
    InjOp_Unknown = 0,
    
    // Memory Operations
    InjOp_Allocate,
    InjOp_Write,
    InjOp_Protect,
    InjOp_Map,
    InjOp_Unmap,
    
    // Thread Operations
    InjOp_CreateThread,
    InjOp_SetContext,
    InjOp_QueueAPC,
    InjOp_ResumeThread,
    
    // Handle Operations
    InjOp_OpenProcess,
    InjOp_DuplicateHandle,
    
    // Other
    InjOp_LoadLibrary,
    InjOp_CreateSection,
    
} INJ_OPERATION_TYPE;

//=============================================================================
// Injection Operation Record
//=============================================================================

typedef struct _INJ_OPERATION {
    //
    // Operation details
    //
    INJ_OPERATION_TYPE Type;
    LARGE_INTEGER Timestamp;
    
    //
    // Source/Target
    //
    HANDLE SourcePid;
    HANDLE TargetPid;
    HANDLE SourceTid;
    
    //
    // Memory details (for memory ops)
    //
    PVOID TargetAddress;
    SIZE_T Size;
    ULONG Protection;
    ULONG OldProtection;
    
    //
    // Thread details (for thread ops)
    //
    HANDLE CreatedThreadId;
    PVOID StartAddress;
    PVOID Parameter;
    
    //
    // Section details
    //
    PVOID SectionObject;
    ULONG64 SectionOffset;
    
    //
    // Call stack
    //
    PVOID ReturnAddress;
    PVOID CallStack[8];
    ULONG CallStackDepth;
    
    //
    // Correlation
    //
    ULONG64 CorrelationId;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY TargetListEntry;
    
} INJ_OPERATION, *PINJ_OPERATION;

//=============================================================================
// Injection Chain
//=============================================================================

typedef struct _INJ_CHAIN {
    //
    // Chain identification
    //
    ULONG64 ChainId;
    INJ_TECHNIQUE DetectedTechnique;
    
    //
    // Source and target
    //
    HANDLE SourcePid;
    HANDLE TargetPid;
    UNICODE_STRING SourceName;
    UNICODE_STRING TargetName;
    
    //
    // Operations in chain
    //
    LIST_ENTRY OperationList;
    ULONG OperationCount;
    
    //
    // Timing
    //
    LARGE_INTEGER FirstOperation;
    LARGE_INTEGER LastOperation;
    ULONG DurationMs;
    
    //
    // Chain state
    //
    BOOLEAN IsComplete;                 // All injection steps seen
    BOOLEAN WasBlocked;
    
    //
    // Confidence
    //
    ULONG ConfidenceScore;              // 0-100
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} INJ_CHAIN, *PINJ_CHAIN;

//=============================================================================
// Detection Result
//=============================================================================

typedef struct _INJ_DETECTION_RESULT {
    //
    // Detection summary
    //
    BOOLEAN InjectionDetected;
    INJ_TECHNIQUE Technique;
    ULONG ConfidenceScore;
    ULONG SeverityScore;
    
    //
    // Attack details
    //
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    UNICODE_STRING SourceProcessName;
    UNICODE_STRING TargetProcessName;
    
    //
    // Injection details
    //
    PVOID InjectedAddress;
    SIZE_T InjectedSize;
    ULONG InjectedProtection;
    
    //
    // Thread details (if applicable)
    //
    HANDLE InjectedThreadId;
    PVOID ThreadStartAddress;
    BOOLEAN ThreadStarted;
    
    //
    // Chain reference
    //
    PINJ_CHAIN Chain;
    
    //
    // MITRE mapping
    //
    ULONG MitreId;                      // T1055.xxx
    CHAR MitreName[64];
    
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
    PEPROCESS Process;
    UNICODE_STRING ProcessName;
    
    //
    // Operations targeting this process
    //
    LIST_ENTRY InboundOperations;
    KSPIN_LOCK InboundLock;
    volatile LONG InboundCount;
    
    //
    // Operations from this process
    //
    LIST_ENTRY OutboundOperations;
    KSPIN_LOCK OutboundLock;
    volatile LONG OutboundCount;
    
    //
    // Active injection chains
    //
    LIST_ENTRY ActiveChains;
    volatile LONG ChainCount;
    
    //
    // Suspicion level
    //
    ULONG SuspicionScore;
    BOOLEAN IsHighRisk;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} INJ_PROCESS_CONTEXT, *PINJ_PROCESS_CONTEXT;

//=============================================================================
// Injection Detector
//=============================================================================

typedef struct _INJ_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Process contexts
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;
    
    //
    // Operation pool
    //
    struct {
        LIST_ENTRY FreeList;
        KSPIN_LOCK Lock;
        PINJ_OPERATION PoolMemory;
        volatile LONG FreeCount;
        ULONG PoolSize;
    } OperationPool;
    
    //
    // Chain tracking
    //
    volatile LONG64 NextChainId;
    
    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    
    //
    // Configuration
    //
    struct {
        ULONG OperationTimeoutMs;
        ULONG MinConfidenceToReport;
        BOOLEAN BlockDetectedInjections;
        BOOLEAN TrackAllProcesses;
    } Config;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 OperationsTracked;
        volatile LONG64 InjectionsDetected;
        volatile LONG64 InjectionsBlocked;
        volatile LONG64 ChainsFormed;
        LARGE_INTEGER StartTime;
    } Stats;
    
} INJ_DETECTOR, *PINJ_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*INJ_DETECTION_CALLBACK)(
    _In_ PINJ_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

typedef BOOLEAN (*INJ_BLOCK_CALLBACK)(
    _In_ PINJ_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
InjInitialize(
    _Out_ PINJ_DETECTOR* Detector
    );

VOID
InjShutdown(
    _Inout_ PINJ_DETECTOR Detector
    );

//=============================================================================
// Public API - Operation Recording
//=============================================================================

NTSTATUS
InjRecordMemoryAlloc(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG Protection
    );

NTSTATUS
InjRecordMemoryWrite(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ PVOID Address,
    _In_ SIZE_T Size
    );

NTSTATUS
InjRecordProtectionChange(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG NewProtection,
    _In_ ULONG OldProtection
    );

NTSTATUS
InjRecordThreadCreation(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE ThreadId,
    _In_ PVOID StartAddress,
    _In_opt_ PVOID Parameter
    );

NTSTATUS
InjRecordAPCQueue(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid,
    _In_ PVOID ApcRoutine
    );

NTSTATUS
InjRecordSectionMap(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ PVOID SectionObject,
    _In_ PVOID ViewBase,
    _In_ SIZE_T ViewSize
    );

//=============================================================================
// Public API - Detection
//=============================================================================

NTSTATUS
InjAnalyzeProcess(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PINJ_DETECTION_RESULT* Result
    );

NTSTATUS
InjCheckForInjection(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE TargetPid,
    _Out_ PBOOLEAN InjectionDetected,
    _Out_opt_ PINJ_TECHNIQUE Technique
    );

//=============================================================================
// Public API - Chain Management
//=============================================================================

NTSTATUS
InjGetActiveChains(
    _In_ PINJ_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxChains, *ChainCount) PINJ_CHAIN* Chains,
    _In_ ULONG MaxChains,
    _Out_ PULONG ChainCount
    );

VOID
InjFreeChain(
    _In_ PINJ_CHAIN Chain
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
InjRegisterDetectionCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

NTSTATUS
InjRegisterBlockCallback(
    _In_ PINJ_DETECTOR Detector,
    _In_ INJ_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
InjUnregisterCallbacks(
    _In_ PINJ_DETECTOR Detector
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
InjFreeResult(
    _In_ PINJ_DETECTION_RESULT Result
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _INJ_STATISTICS {
    ULONG TrackedProcesses;
    ULONG64 OperationsTracked;
    ULONG64 InjectionsDetected;
    ULONG64 InjectionsBlocked;
    ULONG64 ChainsFormed;
    LARGE_INTEGER UpTime;
} INJ_STATISTICS, *PINJ_STATISTICS;

NTSTATUS
InjGetStatistics(
    _In_ PINJ_DETECTOR Detector,
    _Out_ PINJ_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
