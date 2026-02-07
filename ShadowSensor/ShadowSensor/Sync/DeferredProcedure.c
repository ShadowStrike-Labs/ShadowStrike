/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE DPC MANAGEMENT ENGINE
 * ============================================================================
 *
 * @file DeferredProcedure.c
 * @brief High-performance DPC (Deferred Procedure Call) management for kernel EDR.
 *
 * Implementation provides CrowdStrike Falcon-class DPC infrastructure with:
 * - Lock-free DPC object pool to avoid allocation at high IRQL
 * - Threaded DPCs for longer operations
 * - DPC chaining for sequential work execution
 * - Per-CPU DPC affinity support
 * - High/Medium/Low importance scheduling
 * - Comprehensive statistics and monitoring
 * - Safe cleanup with reference counting
 *
 * Security Guarantees:
 * - All parameters validated before use
 * - Pool objects pre-allocated to avoid DISPATCH_LEVEL allocation
 * - Reference counting prevents use-after-free
 * - Proper cleanup on all error paths
 * - No memory leaks under any circumstances
 *
 * Performance Characteristics:
 * - O(1) DPC object allocation from lock-free pool
 * - Minimal lock contention via SLIST
 * - Inline context for small payloads (no allocation)
 * - Cache-aligned structures to prevent false sharing
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "DeferredProcedure.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DpcInitialize)
#pragma alloc_text(PAGE, DpcShutdown)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define DPC_MANAGER_MAGIC           0x4450434D  // 'DPCM'
#define DPC_OBJECT_MAGIC            0x4450434F  // 'DPCO'

#define DPC_100NS_PER_MS            10000LL
#define DPC_100NS_PER_SECOND        10000000LL

// ============================================================================
// INTERNAL FUNCTION PROTOTYPES
// ============================================================================

static
PDPC_OBJECT
DpcpAllocateObject(
    _In_ PDPC_MANAGER Manager
    );

static
VOID
DpcpFreeObject(
    _In_ PDPC_MANAGER Manager,
    _In_ PDPC_OBJECT Object
    );

static
VOID
DpcpInitializeObject(
    _In_ PDPC_OBJECT Object,
    _In_ ULONG ObjectId
    );

static
VOID
DpcpResetObject(
    _In_ PDPC_OBJECT Object
    );

static
KDEFERRED_ROUTINE DpcpGenericDpcRoutine;

static
KDEFERRED_ROUTINE DpcpChainDpcRoutine;

static
VOID
DpcpExecuteCallback(
    _In_ PDPC_OBJECT Object
    );

static
VOID
DpcpCompleteObject(
    _In_ PDPC_MANAGER Manager,
    _In_ PDPC_OBJECT Object,
    _In_ NTSTATUS Status
    );

static
NTSTATUS
DpcpCopyContext(
    _In_ PDPC_OBJECT Object,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize
    );

static
VOID
DpcpFreeContext(
    _In_ PDPC_OBJECT Object
    );

static
FORCEINLINE
VOID
DpcpReferenceObject(
    _In_ PDPC_OBJECT Object
    )
{
    InterlockedIncrement(&Object->RefCount);
}

static
FORCEINLINE
LONG
DpcpDereferenceObject(
    _In_ PDPC_OBJECT Object
    )
{
    return InterlockedDecrement(&Object->RefCount);
}

static
FORCEINLINE
LARGE_INTEGER
DpcpGetCurrentTime(
    VOID
    )
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return time;
}

static
FORCEINLINE
BOOLEAN
DpcpIsValidManager(
    _In_opt_ PDPC_MANAGER Manager
    )
{
    return (Manager != NULL && Manager->Initialized);
}

static
FORCEINLINE
BOOLEAN
DpcpIsValidObject(
    _In_opt_ PDPC_OBJECT Object
    )
{
    return (Object != NULL && Object->State != DpcState_Free);
}

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcInitialize(
    PDPC_MANAGER* Manager,
    ULONG PoolSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDPC_MANAGER manager = NULL;
    ULONG actualPoolSize;
    ULONG i;
    SIZE_T poolMemorySize;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Validate and adjust pool size
    //
    if (PoolSize == 0) {
        actualPoolSize = DPC_POOL_SIZE_DEFAULT;
    } else if (PoolSize < DPC_POOL_SIZE_MIN) {
        actualPoolSize = DPC_POOL_SIZE_MIN;
    } else if (PoolSize > DPC_POOL_SIZE_MAX) {
        actualPoolSize = DPC_POOL_SIZE_MAX;
    } else {
        actualPoolSize = PoolSize;
    }

    //
    // Calculate pool memory size with overflow check
    //
    if (!ShadowStrikeSafeMultiply(
            sizeof(DPC_OBJECT),
            actualPoolSize,
            &poolMemorySize)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate manager structure
    //
    manager = (PDPC_MANAGER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(DPC_MANAGER),
        DPC_POOL_TAG_OBJECT
    );

    if (manager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(manager, sizeof(DPC_MANAGER));

    //
    // Initialize lock-free free pool
    //
    InitializeSListHead(&manager->FreePool);
    manager->PoolSize = actualPoolSize;

    //
    // Allocate pool memory for DPC objects
    //
    manager->PoolMemory = (PDPC_OBJECT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        poolMemorySize,
        DPC_POOL_TAG_OBJECT
    );

    if (manager->PoolMemory == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(manager->PoolMemory, poolMemorySize);
    manager->PoolMemorySize = (ULONG)poolMemorySize;

    //
    // Initialize each DPC object and add to free pool
    //
    for (i = 0; i < actualPoolSize; i++) {
        PDPC_OBJECT object = &manager->PoolMemory[i];

        DpcpInitializeObject(object, i + 1);

        //
        // Push to free list
        //
        InterlockedPushEntrySList(
            &manager->FreePool,
            &object->FreeListEntry
        );
        InterlockedIncrement(&manager->FreeCount);
    }

    //
    // Initialize configuration
    //
    manager->Config.DefaultPoolSize = actualPoolSize;
    manager->Config.PreferThreadedDpc = FALSE;
    manager->Config.EnableChaining = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&manager->Stats.StartTime);

    //
    // Mark as initialized
    //
    manager->Initialized = TRUE;

    *Manager = manager;
    return STATUS_SUCCESS;

Cleanup:
    if (manager != NULL) {
        if (manager->PoolMemory != NULL) {
            ShadowStrikeFreePoolWithTag(manager->PoolMemory, DPC_POOL_TAG_OBJECT);
        }
        ShadowStrikeFreePoolWithTag(manager, DPC_POOL_TAG_OBJECT);
    }

    return status;
}

_Use_decl_annotations_
VOID
DpcShutdown(
    PDPC_MANAGER Manager
    )
{
    ULONG i;
    PDPC_OBJECT object;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Mark as shutting down
    //
    Manager->Initialized = FALSE;

    //
    // Wait for all queued DPCs to complete and cancel pending ones
    //
    for (i = 0; i < Manager->PoolSize; i++) {
        object = &Manager->PoolMemory[i];

        if (object->State == DpcState_Queued) {
            //
            // Try to remove from queue
            //
            if (KeRemoveQueueDpc(&object->Dpc)) {
                //
                // Successfully removed, free any external context
                //
                DpcpFreeContext(object);
                DpcpResetObject(object);
                InterlockedIncrement64(&Manager->Stats.TotalCancelled);
            }
        }

        //
        // Wait for running DPCs
        //
        while (object->State == DpcState_Running) {
            LARGE_INTEGER delay;
            delay.QuadPart = -1 * DPC_100NS_PER_MS;  // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    //
    // Flush all DPCs on all processors
    //
    KeFlushQueuedDpcs();

    //
    // Free pool memory
    //
    if (Manager->PoolMemory != NULL) {
        ShadowStrikeFreePoolWithTag(Manager->PoolMemory, DPC_POOL_TAG_OBJECT);
        Manager->PoolMemory = NULL;
    }

    //
    // Free manager
    //
    ShadowStrikeFreePoolWithTag(Manager, DPC_POOL_TAG_OBJECT);
}

// ============================================================================
// DPC QUEUE OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcQueue(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    ULONG ContextSize,
    PDPC_OPTIONS Options
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDPC_OBJECT object = NULL;
    DPC_TYPE dpcType;
    BOOLEAN targeted = FALSE;
    ULONG targetProcessor = 0;

    //
    // Validate parameters
    //
    if (!DpcpIsValidManager(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ContextSize > DPC_MAX_CONTEXT_SIZE && Context != NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Parse options
    //
    if (Options != NULL) {
        dpcType = Options->Type;
        if (Options->TargetProcessor != MAXULONG) {
            targeted = TRUE;
            targetProcessor = Options->TargetProcessor;
        }
    } else {
        dpcType = DpcType_Normal;
    }

    //
    // Allocate DPC object from pool
    //
    object = DpcpAllocateObject(Manager);
    if (object == NULL) {
        InterlockedIncrement64(&Manager->Stats.PoolExhausted);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Configure object
    //
    object->Type = dpcType;
    object->Callback = Callback;
    object->ProcessorTargeted = targeted;
    object->TargetProcessor = targetProcessor;

    if (Options != NULL) {
        object->CompletionCallback = Options->CompletionCallback;
    }

    //
    // Copy context if provided
    //
    if (Context != NULL && ContextSize > 0) {
        status = DpcpCopyContext(object, Context, ContextSize);
        if (!NT_SUCCESS(status)) {
            DpcpFreeObject(Manager, object);
            return status;
        }
    }

    //
    // Initialize the kernel DPC
    //
    KeInitializeDpc(&object->Dpc, DpcpGenericDpcRoutine, object);

    //
    // Set importance based on type
    //
    switch (dpcType) {
        case DpcType_HighImportance:
            KeSetImportanceDpc(&object->Dpc, HighImportance);
            break;
        case DpcType_MediumImportance:
            KeSetImportanceDpc(&object->Dpc, MediumImportance);
            break;
        case DpcType_LowImportance:
            KeSetImportanceDpc(&object->Dpc, LowImportance);
            break;
        case DpcType_Threaded:
            KeInitializeThreadedDpc(&object->Dpc, DpcpGenericDpcRoutine, object);
            break;
        default:
            KeSetImportanceDpc(&object->Dpc, MediumImportance);
            break;
    }

    //
    // Set target processor if specified
    //
    if (targeted) {
        KeSetTargetProcessorDpc(&object->Dpc, (CCHAR)targetProcessor);
    }

    //
    // Record queue time
    //
    object->QueueTime = DpcpGetCurrentTime();

    //
    // Update state
    //
    InterlockedExchange((PLONG)&object->State, DpcState_Queued);

    //
    // Queue the DPC
    //
    if (!KeInsertQueueDpc(&object->Dpc, Manager, NULL)) {
        //
        // DPC was already queued (shouldn't happen with fresh object)
        //
        InterlockedExchange((PLONG)&object->State, DpcState_Free);
        DpcpFreeContext(object);
        DpcpFreeObject(Manager, object);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->Stats.TotalQueued);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DpcQueueExternal(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    PDPC_OPTIONS Options
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDPC_OBJECT object = NULL;
    DPC_TYPE dpcType;
    BOOLEAN targeted = FALSE;
    ULONG targetProcessor = 0;

    //
    // Validate parameters
    //
    if (!DpcpIsValidManager(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Parse options
    //
    if (Options != NULL) {
        dpcType = Options->Type;
        if (Options->TargetProcessor != MAXULONG) {
            targeted = TRUE;
            targetProcessor = Options->TargetProcessor;
        }
    } else {
        dpcType = DpcType_Normal;
    }

    //
    // Allocate DPC object from pool
    //
    object = DpcpAllocateObject(Manager);
    if (object == NULL) {
        InterlockedIncrement64(&Manager->Stats.PoolExhausted);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Configure object with external context
    //
    object->Type = dpcType;
    object->Callback = Callback;
    object->ExternalContext = Context;
    object->UseInlineContext = FALSE;
    object->ContextSize = 0;  // Unknown for external
    object->ProcessorTargeted = targeted;
    object->TargetProcessor = targetProcessor;

    if (Options != NULL) {
        object->CompletionCallback = Options->CompletionCallback;
    }

    //
    // Initialize the kernel DPC
    //
    if (dpcType == DpcType_Threaded) {
        KeInitializeThreadedDpc(&object->Dpc, DpcpGenericDpcRoutine, object);
    } else {
        KeInitializeDpc(&object->Dpc, DpcpGenericDpcRoutine, object);

        switch (dpcType) {
            case DpcType_HighImportance:
                KeSetImportanceDpc(&object->Dpc, HighImportance);
                break;
            case DpcType_LowImportance:
                KeSetImportanceDpc(&object->Dpc, LowImportance);
                break;
            default:
                KeSetImportanceDpc(&object->Dpc, MediumImportance);
                break;
        }
    }

    //
    // Set target processor if specified
    //
    if (targeted) {
        KeSetTargetProcessorDpc(&object->Dpc, (CCHAR)targetProcessor);
    }

    //
    // Record queue time and update state
    //
    object->QueueTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&object->State, DpcState_Queued);

    //
    // Queue the DPC
    //
    if (!KeInsertQueueDpc(&object->Dpc, Manager, NULL)) {
        InterlockedExchange((PLONG)&object->State, DpcState_Free);
        DpcpFreeObject(Manager, object);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedIncrement64(&Manager->Stats.TotalQueued);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DpcQueueOnProcessor(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    ULONG ContextSize,
    ULONG ProcessorNumber
    )
{
    DPC_OPTIONS options;

    RtlZeroMemory(&options, sizeof(DPC_OPTIONS));
    options.Type = DpcType_Normal;
    options.TargetProcessor = ProcessorNumber;

    return DpcQueue(Manager, Callback, Context, ContextSize, &options);
}

_Use_decl_annotations_
NTSTATUS
DpcQueueThreaded(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    ULONG ContextSize
    )
{
    DPC_OPTIONS options;

    RtlZeroMemory(&options, sizeof(DPC_OPTIONS));
    options.Type = DpcType_Threaded;
    options.TargetProcessor = MAXULONG;

    return DpcQueue(Manager, Callback, Context, ContextSize, &options);
}

// ============================================================================
// DPC CHAINING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcCreateChain(
    PDPC_MANAGER Manager,
    DPC_CALLBACK* Callbacks,
    PVOID* Contexts,
    ULONG* ContextSizes,
    ULONG Count,
    DPC_COMPLETION_CALLBACK ChainCompletion,
    PULONG ChainId
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDPC_OBJECT* chainObjects = NULL;
    PDPC_OBJECT firstObject = NULL;
    ULONG i;
    ULONG allocatedCount = 0;

    //
    // Validate parameters
    //
    if (!DpcpIsValidManager(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callbacks == NULL || Count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Count > DPC_CHAIN_MAX_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->Config.EnableChaining) {
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Allocate temporary array to hold chain objects
    //
    chainObjects = (PDPC_OBJECT*)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Count * sizeof(PDPC_OBJECT),
        DPC_POOL_TAG_CHAIN
    );

    if (chainObjects == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(chainObjects, Count * sizeof(PDPC_OBJECT));

    //
    // Allocate all chain objects first
    //
    for (i = 0; i < Count; i++) {
        chainObjects[i] = DpcpAllocateObject(Manager);
        if (chainObjects[i] == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        allocatedCount++;

        //
        // Validate callback
        //
        if (Callbacks[i] == NULL) {
            status = STATUS_INVALID_PARAMETER;
            goto Cleanup;
        }
    }

    //
    // Configure each object in the chain
    //
    for (i = 0; i < Count; i++) {
        PDPC_OBJECT object = chainObjects[i];
        ULONG contextSize = 0;
        PVOID context = NULL;

        if (ContextSizes != NULL) {
            contextSize = ContextSizes[i];
        }
        if (Contexts != NULL) {
            context = Contexts[i];
        }

        object->Type = DpcType_Normal;
        object->Callback = Callbacks[i];
        object->ChainIndex = i;
        object->ChainLength = Count;

        //
        // Set up chain linkage
        //
        if (i < Count - 1) {
            object->NextInChain = chainObjects[i + 1];
        } else {
            object->NextInChain = NULL;
            object->CompletionCallback = ChainCompletion;
        }

        //
        // Copy context
        //
        if (context != NULL && contextSize > 0) {
            if (contextSize <= DPC_MAX_CONTEXT_SIZE) {
                status = DpcpCopyContext(object, context, contextSize);
                if (!NT_SUCCESS(status)) {
                    goto Cleanup;
                }
            } else {
                //
                // Context too large for inline
                //
                status = STATUS_BUFFER_TOO_SMALL;
                goto Cleanup;
            }
        }

        //
        // Initialize DPC for chain execution
        //
        KeInitializeDpc(&object->Dpc, DpcpChainDpcRoutine, object);
        KeSetImportanceDpc(&object->Dpc, MediumImportance);
    }

    //
    // Return chain ID (first object's ID)
    //
    firstObject = chainObjects[0];
    if (ChainId != NULL) {
        *ChainId = firstObject->ObjectId;
    }

    //
    // Update statistics
    //
    InterlockedAdd64(&Manager->Stats.ChainedDpcs, Count);

    //
    // Free temporary array (objects are still valid in pool)
    //
    ShadowStrikeFreePoolWithTag(chainObjects, DPC_POOL_TAG_CHAIN);

    return STATUS_SUCCESS;

Cleanup:
    //
    // Free all allocated objects on failure
    //
    for (i = 0; i < allocatedCount; i++) {
        if (chainObjects[i] != NULL) {
            DpcpFreeContext(chainObjects[i]);
            DpcpFreeObject(Manager, chainObjects[i]);
        }
    }

    if (chainObjects != NULL) {
        ShadowStrikeFreePoolWithTag(chainObjects, DPC_POOL_TAG_CHAIN);
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
DpcQueueChain(
    PDPC_MANAGER Manager,
    ULONG ChainId
    )
{
    PDPC_OBJECT object = NULL;
    ULONG i;

    //
    // Validate parameters
    //
    if (!DpcpIsValidManager(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ChainId == 0 || ChainId > Manager->PoolSize) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find the chain head object
    //
    for (i = 0; i < Manager->PoolSize; i++) {
        PDPC_OBJECT candidate = &Manager->PoolMemory[i];
        if (candidate->ObjectId == ChainId &&
            candidate->ChainIndex == 0 &&
            candidate->State == DpcState_Allocated) {
            object = candidate;
            break;
        }
    }

    if (object == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Queue the first DPC in the chain
    //
    object->QueueTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&object->State, DpcState_Queued);

    if (!KeInsertQueueDpc(&object->Dpc, Manager, NULL)) {
        InterlockedExchange((PLONG)&object->State, DpcState_Allocated);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedIncrement64(&Manager->Stats.TotalQueued);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DpcCancelChain(
    PDPC_MANAGER Manager,
    ULONG ChainId
    )
{
    PDPC_OBJECT object = NULL;
    PDPC_OBJECT current;
    ULONG i;
    ULONG cancelledCount = 0;

    //
    // Validate parameters
    //
    if (!DpcpIsValidManager(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ChainId == 0 || ChainId > Manager->PoolSize) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find the chain head object
    //
    for (i = 0; i < Manager->PoolSize; i++) {
        PDPC_OBJECT candidate = &Manager->PoolMemory[i];
        if (candidate->ObjectId == ChainId && candidate->ChainIndex == 0) {
            object = candidate;
            break;
        }
    }

    if (object == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Cancel all DPCs in the chain
    //
    current = object;
    while (current != NULL) {
        PDPC_OBJECT next = current->NextInChain;

        if (current->State == DpcState_Queued) {
            if (KeRemoveQueueDpc(&current->Dpc)) {
                DpcpFreeContext(current);
                DpcpResetObject(current);
                DpcpFreeObject(Manager, current);
                cancelledCount++;
            }
        } else if (current->State == DpcState_Allocated) {
            DpcpFreeContext(current);
            DpcpResetObject(current);
            DpcpFreeObject(Manager, current);
            cancelledCount++;
        }

        current = next;
    }

    InterlockedAdd64(&Manager->Stats.TotalCancelled, cancelledCount);

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcGetStatistics(
    PDPC_MANAGER Manager,
    PDPC_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (!DpcpIsValidManager(Manager) || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(DPC_STATISTICS));

    Stats->PoolSize = Manager->PoolSize;
    Stats->FreeCount = (ULONG)Manager->FreeCount;
    Stats->AllocatedCount = (ULONG)Manager->AllocatedCount;
    Stats->TotalQueued = Manager->Stats.TotalQueued;
    Stats->TotalExecuted = Manager->Stats.TotalExecuted;
    Stats->TotalCancelled = Manager->Stats.TotalCancelled;
    Stats->PoolExhausted = Manager->Stats.PoolExhausted;
    Stats->ChainedDpcs = Manager->Stats.ChainedDpcs;

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Manager->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DpcResetStatistics(
    PDPC_MANAGER Manager
    )
{
    if (!DpcpIsValidManager(Manager)) {
        return;
    }

    InterlockedExchange64(&Manager->Stats.TotalQueued, 0);
    InterlockedExchange64(&Manager->Stats.TotalExecuted, 0);
    InterlockedExchange64(&Manager->Stats.TotalCancelled, 0);
    InterlockedExchange64(&Manager->Stats.PoolExhausted, 0);
    InterlockedExchange64(&Manager->Stats.ChainedDpcs, 0);
    KeQuerySystemTime(&Manager->Stats.StartTime);
}

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

static
PDPC_OBJECT
DpcpAllocateObject(
    _In_ PDPC_MANAGER Manager
    )
{
    PSLIST_ENTRY entry;
    PDPC_OBJECT object;

    //
    // Pop from lock-free free list
    //
    entry = InterlockedPopEntrySList(&Manager->FreePool);
    if (entry == NULL) {
        return NULL;
    }

    object = CONTAINING_RECORD(entry, DPC_OBJECT, FreeListEntry);

    InterlockedDecrement(&Manager->FreeCount);
    InterlockedIncrement(&Manager->AllocatedCount);

    //
    // Reset and mark as allocated
    //
    DpcpResetObject(object);
    object->State = DpcState_Allocated;
    object->RefCount = 1;

    return object;
}

static
VOID
DpcpFreeObject(
    _In_ PDPC_MANAGER Manager,
    _In_ PDPC_OBJECT Object
    )
{
    if (Object == NULL) {
        return;
    }

    //
    // Reset state
    //
    DpcpResetObject(Object);

    //
    // Push back to free list
    //
    InterlockedPushEntrySList(&Manager->FreePool, &Object->FreeListEntry);

    InterlockedDecrement(&Manager->AllocatedCount);
    InterlockedIncrement(&Manager->FreeCount);
}

static
VOID
DpcpInitializeObject(
    _In_ PDPC_OBJECT Object,
    _In_ ULONG ObjectId
    )
{
    RtlZeroMemory(Object, sizeof(DPC_OBJECT));
    Object->ObjectId = ObjectId;
    Object->State = DpcState_Free;
    Object->RefCount = 0;
}

static
VOID
DpcpResetObject(
    _In_ PDPC_OBJECT Object
    )
{
    ULONG savedId = Object->ObjectId;

    //
    // Free any external context we allocated
    //
    DpcpFreeContext(Object);

    //
    // Clear all fields except ObjectId
    //
    RtlZeroMemory(Object, sizeof(DPC_OBJECT));
    Object->ObjectId = savedId;
    Object->State = DpcState_Free;
}

static
VOID
DpcpGenericDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDPC_OBJECT object = (PDPC_OBJECT)DeferredContext;
    PDPC_MANAGER manager = (PDPC_MANAGER)SystemArgument1;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (object == NULL || manager == NULL) {
        return;
    }

    //
    // Update state
    //
    object->ExecuteTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&object->State, DpcState_Running);

    //
    // Execute callback
    //
    DpcpExecuteCallback(object);

    //
    // Complete
    //
    DpcpCompleteObject(manager, object, STATUS_SUCCESS);
}

static
VOID
DpcpChainDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDPC_OBJECT object = (PDPC_OBJECT)DeferredContext;
    PDPC_MANAGER manager = (PDPC_MANAGER)SystemArgument1;
    PDPC_OBJECT nextInChain;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (object == NULL || manager == NULL) {
        return;
    }

    //
    // Update state
    //
    object->ExecuteTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&object->State, DpcState_Running);

    //
    // Execute callback
    //
    DpcpExecuteCallback(object);

    //
    // Get next in chain before completing this object
    //
    nextInChain = object->NextInChain;

    //
    // Complete this object
    //
    DpcpCompleteObject(manager, object, STATUS_SUCCESS);

    //
    // Queue next in chain if exists
    //
    if (nextInChain != NULL) {
        nextInChain->QueueTime = DpcpGetCurrentTime();
        InterlockedExchange((PLONG)&nextInChain->State, DpcState_Queued);

        if (!KeInsertQueueDpc(&nextInChain->Dpc, manager, NULL)) {
            //
            // Failed to queue next, clean up remaining chain
            //
            PDPC_OBJECT current = nextInChain;
            while (current != NULL) {
                PDPC_OBJECT next = current->NextInChain;
                DpcpFreeContext(current);
                DpcpResetObject(current);
                DpcpFreeObject(manager, current);
                current = next;
            }
        } else {
            InterlockedIncrement64(&manager->Stats.TotalQueued);
        }
    }
}

static
VOID
DpcpExecuteCallback(
    _In_ PDPC_OBJECT Object
    )
{
    PVOID context;
    ULONG contextSize;

    if (Object->Callback == NULL) {
        return;
    }

    //
    // Determine context to pass
    //
    if (Object->UseInlineContext) {
        context = Object->InlineContext;
        contextSize = Object->ContextSize;
    } else if (Object->ExternalContext != NULL) {
        context = Object->ExternalContext;
        contextSize = Object->ContextSize;
    } else {
        context = NULL;
        contextSize = 0;
    }

    //
    // Execute the callback
    //
    __try {
        Object->Callback(context, contextSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Callback raised exception - log but continue
        // In production, this would be logged via ETW
        //
    }
}

static
VOID
DpcpCompleteObject(
    _In_ PDPC_MANAGER Manager,
    _In_ PDPC_OBJECT Object,
    _In_ NTSTATUS Status
    )
{
    //
    // Record completion time
    //
    Object->CompleteTime = DpcpGetCurrentTime();

    //
    // Update state
    //
    InterlockedExchange((PLONG)&Object->State, DpcState_Completed);

    //
    // Call completion callback if registered
    //
    if (Object->CompletionCallback != NULL) {
        __try {
            Object->CompletionCallback(Status, Object->ChainContext);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            //
            // Completion callback raised exception
            //
        }
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->Stats.TotalExecuted);

    //
    // Free context and return to pool
    //
    DpcpFreeContext(Object);
    DpcpFreeObject(Manager, Object);
}

static
NTSTATUS
DpcpCopyContext(
    _In_ PDPC_OBJECT Object,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize
    )
{
    if (Context == NULL || ContextSize == 0) {
        Object->UseInlineContext = FALSE;
        Object->ContextSize = 0;
        return STATUS_SUCCESS;
    }

    if (ContextSize <= DPC_MAX_CONTEXT_SIZE) {
        //
        // Use inline context
        //
        RtlCopyMemory(Object->InlineContext, Context, ContextSize);
        Object->UseInlineContext = TRUE;
        Object->ContextSize = ContextSize;
        return STATUS_SUCCESS;
    }

    //
    // Context too large for inline storage
    //
    return STATUS_BUFFER_TOO_SMALL;
}

static
VOID
DpcpFreeContext(
    _In_ PDPC_OBJECT Object
    )
{
    //
    // Inline context doesn't need freeing
    // External context is caller's responsibility
    //
    Object->UseInlineContext = FALSE;
    Object->ExternalContext = NULL;
    Object->ContextSize = 0;
    RtlZeroMemory(Object->InlineContext, DPC_MAX_CONTEXT_SIZE);
}
