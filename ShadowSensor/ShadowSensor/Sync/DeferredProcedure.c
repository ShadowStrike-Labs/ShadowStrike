/**
 * ============================================================================
 * ShadowStrike NGAV — Enterprise DPC Management
 * ============================================================================
 *
 * @file DeferredProcedure.c
 *
 * Pre-allocated, lock-free DPC object pool for the ShadowStrike kernel
 * sensor.  Provides O(1) DPC object allocation via SLIST at any IRQL
 * up to DISPATCH_LEVEL, threaded-DPC support, per-processor targeting
 * with PROCESSOR_NUMBER (>64 CPU safe), and deterministic shutdown
 * drain via ActiveCount + KEVENT.
 *
 * Design decisions (enterprise rationale):
 *
 *   1. SLIST_ENTRY is the FIRST field in DPC_OBJECT so that the struct's
 *      DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) directive guarantees
 *      the 16-byte alignment required by CMPXCHG16B on x64.
 *
 *   2. No SEH (__try/__except) in DPC callbacks.  DPC routines run at
 *      DISPATCH_LEVEL where SEH is undefined behavior.  Faults must
 *      bugcheck — masking them corrupts kernel state silently.
 *
 *   3. No chaining.  The original chain design stored cross-object
 *      pointers with no ownership model, creating use-after-free and
 *      double-free races between the chain DPC routine and
 *      DpcCancelChain.  Chaining was removed entirely.
 *
 *   4. ActiveCount / DrainEvent replace spin-wait shutdown.  Each DPC
 *      routine increments ActiveCount on entry and decrements on
 *      completion.  DpcShutdown cancels queued DPCs, flushes system
 *      queues, then waits on DrainEvent (signaled when ActiveCount
 *      hits 0 during shutdown).
 *
 *   5. Dead RefCount code removed.  It was never used — false safety
 *      claim.  Lifetime is managed by pool ownership + ActiveCount.
 *
 *   6. KeSetTargetProcessorDpcEx with PROCESSOR_NUMBER replaces
 *      deprecated KeSetTargetProcessorDpc (CCHAR truncation on >64 CPUs).
 *
 *   7. Inline context reduced to 64 bytes (from 256) to keep
 *      DPC_OBJECT small and conserve NonPagedPoolNx.
 *
 * @copyright (c) ShadowStrike Team.  All rights reserved.
 * ============================================================================
 */

#include "DeferredProcedure.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DpcInitialize)
#pragma alloc_text(PAGE, DpcShutdown)
#endif

// ============================================================================
// Internal helpers
// ============================================================================

static PDPC_OBJECT
DpcpAllocateObject(_In_ PDPC_MANAGER Manager);

static VOID
DpcpFreeObject(_In_ PDPC_MANAGER Manager, _In_ PDPC_OBJECT Object);

static VOID
DpcpResetObject(_In_ PDPC_OBJECT Object);

static KDEFERRED_ROUTINE DpcpDpcRoutine;

static VOID
DpcpCompleteObject(_In_ PDPC_MANAGER Manager,
                   _In_ PDPC_OBJECT Object,
                   _In_ NTSTATUS Status);

static NTSTATUS
DpcpCopyContext(_In_ PDPC_OBJECT Object,
                _In_reads_bytes_opt_(ContextSize) PVOID Context,
                _In_ ULONG ContextSize);

static VOID
DpcpClearContext(_In_ PDPC_OBJECT Object);

static FORCEINLINE BOOLEAN
DpcpIsValidManager(_In_opt_ PDPC_MANAGER Manager)
{
    return (Manager != NULL &&
            InterlockedCompareExchange(&Manager->Initialized, 1, 1) == 1);
}

static FORCEINLINE LARGE_INTEGER
DpcpGetCurrentTime(VOID)
{
    LARGE_INTEGER t;
    KeQuerySystemTime(&t);
    return t;
}

// ============================================================================
// DpcInitialize
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcInitialize(
    PDPC_MANAGER* Manager,
    ULONG PoolSize
    )
{
    NTSTATUS status;
    PDPC_MANAGER mgr = NULL;
    ULONG actualSize;
    SIZE_T poolBytes;
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Manager = NULL;

    //
    // Clamp pool size.
    //
    if (PoolSize == 0) {
        actualSize = DPC_POOL_SIZE_DEFAULT;
    } else if (PoolSize < DPC_POOL_SIZE_MIN) {
        actualSize = DPC_POOL_SIZE_MIN;
    } else if (PoolSize > DPC_POOL_SIZE_MAX) {
        actualSize = DPC_POOL_SIZE_MAX;
    } else {
        actualSize = PoolSize;
    }

    //
    // Overflow-safe allocation size.
    //
    if (!ShadowStrikeSafeMultiply(sizeof(DPC_OBJECT), actualSize, &poolBytes)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate manager (NonPagedPoolNx — accessed at DISPATCH_LEVEL).
    //
    mgr = (PDPC_MANAGER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(DPC_MANAGER), DPC_POOL_TAG);
    if (mgr == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(mgr, sizeof(DPC_MANAGER));

    //
    // Allocate object array.
    //
    mgr->PoolMemory = (PDPC_OBJECT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, poolBytes, DPC_POOL_TAG);
    if (mgr->PoolMemory == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    RtlZeroMemory(mgr->PoolMemory, poolBytes);
    mgr->PoolMemorySize = poolBytes;
    mgr->PoolSize = actualSize;

    //
    // Initialize SLIST free pool and push every object.
    //
    InitializeSListHead(&mgr->FreePool);

    for (i = 0; i < actualSize; i++) {
        PDPC_OBJECT obj = &mgr->PoolMemory[i];
        obj->ObjectId = i + 1;
        obj->State = DpcState_Free;
        InterlockedPushEntrySList(&mgr->FreePool, &obj->FreeListEntry);
    }
    mgr->FreeCount = (LONG)actualSize;

    //
    // Drain event — signaled when ActiveCount reaches 0 during shutdown.
    //
    KeInitializeEvent(&mgr->DrainEvent, NotificationEvent, FALSE);

    //
    // Statistics start time.
    //
    KeQuerySystemTime(&mgr->StartTime);

    //
    // Publish — Initialized is the gate for all queue operations.
    //
    InterlockedExchange(&mgr->Initialized, 1);

    *Manager = mgr;
    return STATUS_SUCCESS;

Fail:
    if (mgr->PoolMemory != NULL) {
        ShadowStrikeFreePoolWithTag(mgr->PoolMemory, DPC_POOL_TAG);
    }
    ShadowStrikeFreePoolWithTag(mgr, DPC_POOL_TAG);
    return status;
}

// ============================================================================
// DpcShutdown
// ============================================================================

_Use_decl_annotations_
VOID
DpcShutdown(
    PDPC_MANAGER* Manager
    )
{
    PDPC_MANAGER mgr;
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL || *Manager == NULL) {
        return;
    }

    mgr = *Manager;
    *Manager = NULL;

    //
    // STEP 1: Gate — reject all new DpcQueue calls.
    //
    InterlockedExchange(&mgr->Initialized, 0);

    //
    // STEP 2: Cancel all queued (but not yet running) DPCs.
    //
    for (i = 0; i < mgr->PoolSize; i++) {
        PDPC_OBJECT obj = &mgr->PoolMemory[i];
        if (obj->State == DpcState_Queued) {
            if (KeRemoveQueueDpc(&obj->Dpc)) {
                //
                // Successfully dequeued — dec ActiveCount (was incremented
                // when we called KeInsertQueueDpc successfully).
                // Note: ActiveCount is incremented in the DPC *routine*
                // entry, not at queue time, so we do NOT decrement here.
                // Just reset the object.
                //
                DpcpClearContext(obj);
                DpcpResetObject(obj);
                InterlockedIncrement64(&mgr->TotalCancelled);
            }
        }
    }

    //
    // STEP 3: Flush all system DPC queues.  After this, no DPC from
    // this driver can be pending in any processor's DPC queue.
    //
    KeFlushQueuedDpcs();

    //
    // STEP 4: Wait for any in-flight callbacks to complete.
    // ActiveCount is incremented at DPC routine entry and decremented
    // in DpcpCompleteObject.  If it's already 0, DrainEvent may
    // already be signaled (we set it in the decrement path when
    // Initialized == 0 and count reaches 0).
    //
    if (InterlockedCompareExchange(&mgr->ActiveCount, 0, 0) > 0) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -30LL * 10000000LL;   // 30 seconds
        KeWaitForSingleObject(&mgr->DrainEvent, Executive,
                              KernelMode, FALSE, &timeout);
    }

    //
    // STEP 5: Free resources.
    //
    if (mgr->PoolMemory != NULL) {
        ShadowStrikeFreePoolWithTag(mgr->PoolMemory, DPC_POOL_TAG);
    }
    ShadowStrikeFreePoolWithTag(mgr, DPC_POOL_TAG);
}

// ============================================================================
// DpcQueue  — queue a DPC with inline context copy
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
    PDPC_OBJECT obj;
    DPC_TYPE type;
    NTSTATUS status;

    if (!DpcpIsValidManager(Manager) || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Context != NULL && ContextSize > DPC_MAX_CONTEXT_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Allocate from free pool.
    //
    obj = DpcpAllocateObject(Manager);
    if (obj == NULL) {
        InterlockedIncrement64(&Manager->PoolExhausted);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Parse options.
    //
    type = DpcType_Normal;
    if (Options != NULL) {
        type = Options->Type;
        obj->CompletionCallback = Options->CompletionCallback;
        obj->CompletionContext  = Options->CompletionContext;
        if (Options->Targeted) {
            obj->TargetProcessor  = Options->TargetProcessor;
            obj->ProcessorTargeted = TRUE;
        }
    }
    obj->Type     = type;
    obj->Callback = Callback;

    //
    // Copy inline context.
    //
    if (Context != NULL && ContextSize > 0) {
        status = DpcpCopyContext(obj, Context, ContextSize);
        if (!NT_SUCCESS(status)) {
            DpcpFreeObject(Manager, obj);
            return status;
        }
    }

    //
    // Initialize kernel DPC — either normal or threaded, never both.
    //
    if (type == DpcType_Threaded) {
        KeInitializeThreadedDpc(&obj->Dpc, DpcpDpcRoutine, obj);
    } else {
        KeInitializeDpc(&obj->Dpc, DpcpDpcRoutine, obj);
        switch (type) {
        case DpcType_HighImportance:
            KeSetImportanceDpc(&obj->Dpc, HighImportance);
            break;
        case DpcType_LowImportance:
            KeSetImportanceDpc(&obj->Dpc, LowImportance);
            break;
        default:
            KeSetImportanceDpc(&obj->Dpc, MediumImportance);
            break;
        }
    }

    //
    // Processor targeting — use Ex variant for >64 CPU support.
    //
    if (obj->ProcessorTargeted) {
        status = KeSetTargetProcessorDpcEx(&obj->Dpc, &obj->TargetProcessor);
        if (!NT_SUCCESS(status)) {
            DpcpClearContext(obj);
            DpcpFreeObject(Manager, obj);
            return status;
        }
    }

    //
    // Record queue time, transition to Queued.
    //
    obj->QueueTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&obj->State, DpcState_Queued);

    //
    // Insert into kernel DPC queue.  SystemArgument1 carries the
    // Manager pointer so the DPC routine can complete the object.
    //
    if (!KeInsertQueueDpc(&obj->Dpc, Manager, NULL)) {
        InterlockedExchange((PLONG)&obj->State, DpcState_Free);
        DpcpClearContext(obj);
        DpcpFreeObject(Manager, obj);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedIncrement64(&Manager->TotalQueued);
    return STATUS_SUCCESS;
}

// ============================================================================
// DpcQueueExternal — caller-managed context lifetime
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcQueueExternal(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    ULONG ContextSize,
    PDPC_OPTIONS Options
    )
{
    PDPC_OBJECT obj;
    DPC_TYPE type;
    NTSTATUS status;

    if (!DpcpIsValidManager(Manager) || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    obj = DpcpAllocateObject(Manager);
    if (obj == NULL) {
        InterlockedIncrement64(&Manager->PoolExhausted);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    type = DpcType_Normal;
    if (Options != NULL) {
        type = Options->Type;
        obj->CompletionCallback = Options->CompletionCallback;
        obj->CompletionContext  = Options->CompletionContext;
        if (Options->Targeted) {
            obj->TargetProcessor  = Options->TargetProcessor;
            obj->ProcessorTargeted = TRUE;
        }
    }

    obj->Type            = type;
    obj->Callback        = Callback;
    obj->ExternalContext = Context;
    obj->UseInlineContext = FALSE;
    obj->ContextSize     = ContextSize;

    if (type == DpcType_Threaded) {
        KeInitializeThreadedDpc(&obj->Dpc, DpcpDpcRoutine, obj);
    } else {
        KeInitializeDpc(&obj->Dpc, DpcpDpcRoutine, obj);
        switch (type) {
        case DpcType_HighImportance:
            KeSetImportanceDpc(&obj->Dpc, HighImportance);
            break;
        case DpcType_LowImportance:
            KeSetImportanceDpc(&obj->Dpc, LowImportance);
            break;
        default:
            KeSetImportanceDpc(&obj->Dpc, MediumImportance);
            break;
        }
    }

    if (obj->ProcessorTargeted) {
        status = KeSetTargetProcessorDpcEx(&obj->Dpc, &obj->TargetProcessor);
        if (!NT_SUCCESS(status)) {
            DpcpFreeObject(Manager, obj);
            return status;
        }
    }

    obj->QueueTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&obj->State, DpcState_Queued);

    if (!KeInsertQueueDpc(&obj->Dpc, Manager, NULL)) {
        InterlockedExchange((PLONG)&obj->State, DpcState_Free);
        DpcpFreeObject(Manager, obj);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedIncrement64(&Manager->TotalQueued);
    return STATUS_SUCCESS;
}

// ============================================================================
// DpcQueueOnProcessor — convenience wrapper
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcQueueOnProcessor(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    ULONG ContextSize,
    USHORT ProcessorGroup,
    UCHAR ProcessorNumber
    )
{
    DPC_OPTIONS opts;
    RtlZeroMemory(&opts, sizeof(opts));
    opts.Type = DpcType_Normal;
    opts.Targeted = TRUE;
    opts.TargetProcessor.Group  = ProcessorGroup;
    opts.TargetProcessor.Number = ProcessorNumber;
    return DpcQueue(Manager, Callback, Context, ContextSize, &opts);
}

// ============================================================================
// DpcQueueThreaded — convenience wrapper
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcQueueThreaded(
    PDPC_MANAGER Manager,
    DPC_CALLBACK Callback,
    PVOID Context,
    ULONG ContextSize
    )
{
    DPC_OPTIONS opts;
    RtlZeroMemory(&opts, sizeof(opts));
    opts.Type = DpcType_Threaded;
    return DpcQueue(Manager, Callback, Context, ContextSize, &opts);
}

// ============================================================================
// DpcGetStatistics
// ============================================================================

_Use_decl_annotations_
NTSTATUS
DpcGetStatistics(
    PDPC_MANAGER Manager,
    PDPC_STATISTICS Stats
    )
{
    LARGE_INTEGER now;

    if (!DpcpIsValidManager(Manager) || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));

    Stats->PoolSize       = Manager->PoolSize;
    Stats->FreeCount      = (ULONG)Manager->FreeCount;
    Stats->AllocatedCount = (ULONG)Manager->AllocatedCount;
    Stats->TotalQueued    = (ULONG64)Manager->TotalQueued;
    Stats->TotalExecuted  = (ULONG64)Manager->TotalExecuted;
    Stats->TotalCancelled = (ULONG64)Manager->TotalCancelled;
    Stats->PoolExhausted  = (ULONG64)Manager->PoolExhausted;

    KeQuerySystemTime(&now);
    Stats->UpTime.QuadPart = now.QuadPart - Manager->StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: DpcpAllocateObject  (any IRQL <= DISPATCH)
// ============================================================================

static
PDPC_OBJECT
DpcpAllocateObject(
    _In_ PDPC_MANAGER Manager
    )
{
    PSLIST_ENTRY entry;
    PDPC_OBJECT obj;

    entry = InterlockedPopEntrySList(&Manager->FreePool);
    if (entry == NULL) {
        return NULL;
    }

    //
    // FreeListEntry is the FIRST field, so CONTAINING_RECORD is a
    // no-op cast — but we use it for type safety.
    //
    obj = CONTAINING_RECORD(entry, DPC_OBJECT, FreeListEntry);

    InterlockedDecrement(&Manager->FreeCount);
    InterlockedIncrement(&Manager->AllocatedCount);

    //
    // Selective reset — clear only the mutable fields, not the
    // entire 200+ byte struct (avoids wasting cycles at DISPATCH).
    //
    DpcpResetObject(obj);
    obj->State = DpcState_Allocated;

    return obj;
}

// ============================================================================
// Internal: DpcpFreeObject  (any IRQL <= DISPATCH)
// ============================================================================

static
VOID
DpcpFreeObject(
    _In_ PDPC_MANAGER Manager,
    _In_ PDPC_OBJECT Object
    )
{
    DpcpResetObject(Object);

    InterlockedPushEntrySList(&Manager->FreePool, &Object->FreeListEntry);

    InterlockedDecrement(&Manager->AllocatedCount);
    InterlockedIncrement(&Manager->FreeCount);
}

// ============================================================================
// Internal: DpcpResetObject
//
// Selectively clears mutable fields instead of RtlZeroMemory on the
// entire struct.  This avoids zeroing the KDPC and FreeListEntry
// (which could be in use by the SLIST infrastructure) and saves
// cycles in the hot DPC completion path at DISPATCH_LEVEL.
// ObjectId is stable across reuse and is NOT cleared.
// ============================================================================

static
VOID
DpcpResetObject(
    _In_ PDPC_OBJECT Object
    )
{
    Object->State              = DpcState_Free;
    Object->Type               = DpcType_Normal;
    Object->Callback           = NULL;
    Object->CompletionCallback = NULL;
    Object->CompletionContext  = NULL;
    Object->ExternalContext    = NULL;
    Object->ContextSize        = 0;
    Object->UseInlineContext   = FALSE;
    Object->ProcessorTargeted  = FALSE;
    Object->QueueTime.QuadPart = 0;
    Object->ExecuteTime.QuadPart = 0;
    Object->CompleteTime.QuadPart = 0;

    //
    // Zero inline context to prevent info-leak of prior DPC data.
    //
    RtlZeroMemory(Object->InlineContext, DPC_MAX_CONTEXT_SIZE);
    RtlZeroMemory(&Object->TargetProcessor, sizeof(PROCESSOR_NUMBER));
}

// ============================================================================
// Internal: DpcpDpcRoutine  (runs at DISPATCH_LEVEL for normal DPCs)
//
// This is the single DPC routine for all queued DPCs.
// ActiveCount tracks in-flight callbacks for deterministic shutdown.
// No SEH — faults at DISPATCH_LEVEL must bugcheck, not be silenced.
// ============================================================================

static
VOID
DpcpDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDPC_OBJECT obj = (PDPC_OBJECT)DeferredContext;
    PDPC_MANAGER mgr = (PDPC_MANAGER)SystemArgument1;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (obj == NULL || mgr == NULL) {
        return;
    }

    //
    // Track in-flight callbacks for shutdown drain.
    //
    InterlockedIncrement(&mgr->ActiveCount);

    obj->ExecuteTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&obj->State, DpcState_Running);

    //
    // Execute the user callback.  No SEH — if this faults, the
    // system must bugcheck.  Masking exceptions at DISPATCH_LEVEL
    // is undefined behavior and silently corrupts kernel state.
    //
    if (obj->Callback != NULL) {
        PVOID ctx;
        ULONG ctxSize;

        if (obj->UseInlineContext) {
            ctx     = obj->InlineContext;
            ctxSize = obj->ContextSize;
        } else if (obj->ExternalContext != NULL) {
            ctx     = obj->ExternalContext;
            ctxSize = obj->ContextSize;
        } else {
            ctx     = NULL;
            ctxSize = 0;
        }

        obj->Callback(ctx, ctxSize);
    }

    //
    // Complete: stats, optional completion callback, return to pool.
    //
    DpcpCompleteObject(mgr, obj, STATUS_SUCCESS);
}

// ============================================================================
// Internal: DpcpCompleteObject
//
// Runs at DISPATCH_LEVEL (or PASSIVE for threaded DPCs).
// Decrements ActiveCount and signals DrainEvent if the manager is
// shutting down and all callbacks have finished.
// ============================================================================

static
VOID
DpcpCompleteObject(
    _In_ PDPC_MANAGER Manager,
    _In_ PDPC_OBJECT Object,
    _In_ NTSTATUS Status
    )
{
    LONG remaining;

    Object->CompleteTime = DpcpGetCurrentTime();
    InterlockedExchange((PLONG)&Object->State, DpcState_Completed);

    //
    // Fire optional completion callback (no SEH — same rationale).
    //
    if (Object->CompletionCallback != NULL) {
        Object->CompletionCallback(Status, Object->CompletionContext);
    }

    InterlockedIncrement64(&Manager->TotalExecuted);

    //
    // Return object to free pool.
    //
    DpcpClearContext(Object);
    DpcpFreeObject(Manager, Object);

    //
    // Decrement in-flight counter.  If we're shutting down
    // (Initialized == 0) and this was the last active DPC,
    // signal the drain event so DpcShutdown can proceed.
    //
    remaining = InterlockedDecrement(&Manager->ActiveCount);
    if (remaining == 0 &&
        InterlockedCompareExchange(&Manager->Initialized, 0, 0) == 0) {
        KeSetEvent(&Manager->DrainEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// Internal: DpcpCopyContext
// ============================================================================

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

    if (ContextSize > DPC_MAX_CONTEXT_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Object->InlineContext, Context, ContextSize);
    Object->UseInlineContext = TRUE;
    Object->ContextSize = ContextSize;
    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: DpcpClearContext
// ============================================================================

static
VOID
DpcpClearContext(
    _In_ PDPC_OBJECT Object
    )
{
    Object->UseInlineContext = FALSE;
    Object->ExternalContext = NULL;
    Object->ContextSize = 0;
    RtlZeroMemory(Object->InlineContext, DPC_MAX_CONTEXT_SIZE);
}
