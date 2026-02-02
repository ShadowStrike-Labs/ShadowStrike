/*++
    ShadowStrike Next-Generation Antivirus
    Module: DeferredProcedure.h
    
    Purpose: DPC (Deferred Procedure Call) management for
             high-priority deferred work at DISPATCH_LEVEL.
             
    Architecture:
    - DPC object pool to avoid allocation at high IRQL
    - Threaded DPCs for longer operations
    - DPC chaining for sequential work
    - Per-CPU DPC affinity support
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define DPC_POOL_TAG_OBJECT     'OCPD'  // DPC - Object
#define DPC_POOL_TAG_CONTEXT    'XCPD'  // DPC - Context
#define DPC_POOL_TAG_CHAIN      'HCPD'  // DPC - Chain

//=============================================================================
// Configuration Constants
//=============================================================================

#define DPC_POOL_SIZE_DEFAULT       256     // Pre-allocated DPCs
#define DPC_POOL_SIZE_MIN           32
#define DPC_POOL_SIZE_MAX           4096
#define DPC_MAX_CONTEXT_SIZE        256     // Inline context size
#define DPC_CHAIN_MAX_LENGTH        16      // Max DPCs in a chain
#define DPC_THREADED_STACK_SIZE     (16 * 1024)  // 16 KB

//=============================================================================
// DPC Types
//=============================================================================

typedef enum _DPC_TYPE {
    DpcType_Normal = 0,                 // Normal DPC
    DpcType_Threaded,                   // Threaded DPC (can block)
    DpcType_HighImportance,             // High importance (front of queue)
    DpcType_MediumImportance,           // Medium importance
    DpcType_LowImportance               // Low importance (back of queue)
} DPC_TYPE;

//=============================================================================
// DPC State
//=============================================================================

typedef enum _DPC_STATE {
    DpcState_Free = 0,
    DpcState_Allocated,
    DpcState_Queued,
    DpcState_Running,
    DpcState_Completed
} DPC_STATE;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*DPC_CALLBACK)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

typedef VOID (*DPC_COMPLETION_CALLBACK)(
    _In_ NTSTATUS Status,
    _In_opt_ PVOID Context
    );

//=============================================================================
// DPC Object
//=============================================================================

typedef struct _DPC_OBJECT {
    //
    // Kernel DPC
    //
    KDPC Dpc;
    
    //
    // Object identification
    //
    ULONG ObjectId;
    DPC_TYPE Type;
    volatile DPC_STATE State;
    
    //
    // Callback
    //
    DPC_CALLBACK Callback;
    DPC_COMPLETION_CALLBACK CompletionCallback;
    
    //
    // Context (inline for small contexts)
    //
    UCHAR InlineContext[DPC_MAX_CONTEXT_SIZE];
    PVOID ExternalContext;
    ULONG ContextSize;
    BOOLEAN UseInlineContext;
    
    //
    // Targeting
    //
    ULONG TargetProcessor;
    BOOLEAN ProcessorTargeted;
    
    //
    // Chaining
    //
    struct _DPC_OBJECT* NextInChain;
    ULONG ChainIndex;
    ULONG ChainLength;
    PVOID ChainContext;
    
    //
    // Statistics
    //
    LARGE_INTEGER QueueTime;
    LARGE_INTEGER ExecuteTime;
    LARGE_INTEGER CompleteTime;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage (for free pool)
    //
    SLIST_ENTRY FreeListEntry;
    
} DPC_OBJECT, *PDPC_OBJECT;

//=============================================================================
// DPC Manager
//=============================================================================

typedef struct _DPC_MANAGER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Object pool (lock-free)
    //
    SLIST_HEADER FreePool;
    volatile LONG FreeCount;
    volatile LONG AllocatedCount;
    ULONG PoolSize;
    
    //
    // Pool backing memory
    //
    PDPC_OBJECT PoolMemory;
    ULONG PoolMemorySize;
    
    //
    // ID generation
    //
    volatile LONG NextObjectId;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalQueued;
        volatile LONG64 TotalExecuted;
        volatile LONG64 TotalCancelled;
        volatile LONG64 PoolExhausted;
        volatile LONG64 ChainedDpcs;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ULONG DefaultPoolSize;
        BOOLEAN PreferThreadedDpc;
        BOOLEAN EnableChaining;
    } Config;
    
} DPC_MANAGER, *PDPC_MANAGER;

//=============================================================================
// DPC Options
//=============================================================================

typedef struct _DPC_OPTIONS {
    DPC_TYPE Type;
    ULONG TargetProcessor;              // Set to MAXULONG for any CPU
    DPC_COMPLETION_CALLBACK CompletionCallback;
    PVOID CompletionContext;
} DPC_OPTIONS, *PDPC_OPTIONS;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Initialize the DPC manager
//
NTSTATUS
DpcInitialize(
    _Out_ PDPC_MANAGER* Manager,
    _In_ ULONG PoolSize
    );

//
// Shutdown the DPC manager
//
VOID
DpcShutdown(
    _Inout_ PDPC_MANAGER Manager
    );

//=============================================================================
// Public API - DPC Operations
//=============================================================================

//
// Queue a DPC with inline context
//
NTSTATUS
DpcQueue(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PDPC_OPTIONS Options
    );

//
// Queue a DPC with external context (caller manages lifetime)
//
NTSTATUS
DpcQueueExternal(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_ PVOID Context,
    _In_opt_ PDPC_OPTIONS Options
    );

//
// Queue a DPC targeted at specific processor
//
NTSTATUS
DpcQueueOnProcessor(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ ULONG ProcessorNumber
    );

//
// Queue a threaded DPC (can run at PASSIVE_LEVEL)
//
NTSTATUS
DpcQueueThreaded(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize
    );

//=============================================================================
// Public API - DPC Chaining
//=============================================================================

//
// Create a chain of DPCs to execute sequentially
//
NTSTATUS
DpcCreateChain(
    _In_ PDPC_MANAGER Manager,
    _In_reads_(Count) DPC_CALLBACK* Callbacks,
    _In_reads_opt_(Count) PVOID* Contexts,
    _In_reads_opt_(Count) ULONG* ContextSizes,
    _In_ ULONG Count,
    _In_opt_ DPC_COMPLETION_CALLBACK ChainCompletion,
    _Out_opt_ PULONG ChainId
    );

//
// Queue a chain
//
NTSTATUS
DpcQueueChain(
    _In_ PDPC_MANAGER Manager,
    _In_ ULONG ChainId
    );

//
// Cancel a chain
//
NTSTATUS
DpcCancelChain(
    _In_ PDPC_MANAGER Manager,
    _In_ ULONG ChainId
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _DPC_STATISTICS {
    ULONG PoolSize;
    ULONG FreeCount;
    ULONG AllocatedCount;
    ULONG64 TotalQueued;
    ULONG64 TotalExecuted;
    ULONG64 TotalCancelled;
    ULONG64 PoolExhausted;
    ULONG64 ChainedDpcs;
    LARGE_INTEGER UpTime;
} DPC_STATISTICS, *PDPC_STATISTICS;

NTSTATUS
DpcGetStatistics(
    _In_ PDPC_MANAGER Manager,
    _Out_ PDPC_STATISTICS Stats
    );

VOID
DpcResetStatistics(
    _Inout_ PDPC_MANAGER Manager
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Quick queue macros
//
#define DpcQueueNormal(Manager, Callback, Context, Size) \
    DpcQueue(Manager, Callback, Context, Size, NULL)

#define DpcQueueHigh(Manager, Callback, Context, Size) \
    do { \
        DPC_OPTIONS _opts = { .Type = DpcType_HighImportance }; \
        DpcQueue(Manager, Callback, Context, Size, &_opts); \
    } while (0)

#ifdef __cplusplus
}
#endif
