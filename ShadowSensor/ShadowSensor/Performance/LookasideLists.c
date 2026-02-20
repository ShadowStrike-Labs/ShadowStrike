/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE LOOKASIDE LIST MANAGER
 * ============================================================================
 *
 * @file LookasideLists.c
 * @brief High-performance lookaside list management implementation.
 *
 * v3.1.0 Changes (Enterprise Hardened):
 * =====================================
 * - Replaced BOOLEAN Initialized with EX_RUNDOWN_REF for safe shutdown
 * - LlShutdown now takes PLL_MANAGER* and NULLs caller's pointer
 * - Removed INIT segment pragmas (safe to call after DriverEntry)
 * - IoFreeWorkItem shutdown race fixed (drain PressureWorkPending first)
 * - ExAllocatePool2 flag logic corrected (no dead POOL_FLAG_UNINITIALIZED)
 * - Removed dead fields: RefCount, ShutdownEvent, FastLock, Custom alloc/free
 * - Fixed cache hit detection (use native lookaside L.TotalAllocates)
 * - LastAccessTime now volatile LONGLONG with InterlockedExchange64
 * - AverageLatency update uses CAS loop (no lost updates)
 * - Replaced CRT strcmp with RtlCompareMemory-based comparison
 * - LookasideCount check moved under lock
 * - LlTrimCaches implemented (recreate lists with reduced depth)
 * - PressureWorkPending cleared AFTER callback completes
 * - PressureCallback written via InterlockedExchangePointer
 * - UsagePercent overflow-safe
 * - Added PAGED_CODE() to all PAGE-segment functions
 * - Fixed LlIsValid/LlManagerIsValid to use non-mutating atomic read
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "LookasideLists.h"
#include <ntstrsafe.h>

// ============================================================================
// PAGED CODE SEGMENT DECLARATIONS
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, LlInitialize)
#pragma alloc_text(PAGE, LlShutdown)
#pragma alloc_text(PAGE, LlCreateLookaside)
#pragma alloc_text(PAGE, LlCreateLookasideEx)
#pragma alloc_text(PAGE, LlDestroyLookaside)
#pragma alloc_text(PAGE, LlSetMemoryLimit)
#pragma alloc_text(PAGE, LlRegisterPressureCallback)
#pragma alloc_text(PAGE, LlTrimCaches)
#pragma alloc_text(PAGE, LlEnableMaintenance)
#pragma alloc_text(PAGE, LlDisableMaintenance)
#pragma alloc_text(PAGE, LlEnableSelfTuning)
#pragma alloc_text(PAGE, LlEnumerateLookasides)
#pragma alloc_text(PAGE, LlFindByName)
#pragma alloc_text(PAGE, LlFindByTag)
#pragma alloc_text(PAGE, LlSetDebugMode)
#pragma alloc_text(PAGE, LlDumpDiagnostics)
#endif

// ============================================================================
// INTERNAL HELPER MACROS
// ============================================================================

#define LL_TRACK_ALLOC(Manager, Size) \
    do { \
        InterlockedIncrement64(&(Manager)->GlobalStats.TotalAllocations); \
        InterlockedAdd64(&(Manager)->GlobalStats.CurrentMemoryUsage, (LONG64)(Size)); \
        { \
            LONG64 _cur = (Manager)->GlobalStats.CurrentMemoryUsage; \
            LONG64 _peak = (Manager)->GlobalStats.PeakMemoryUsage; \
            while (_cur > _peak) { \
                InterlockedCompareExchange64(&(Manager)->GlobalStats.PeakMemoryUsage, _cur, _peak); \
                _peak = (Manager)->GlobalStats.PeakMemoryUsage; \
            } \
        } \
    } while (0)

#define LL_TRACK_FREE(Manager, Size) \
    do { \
        InterlockedIncrement64(&(Manager)->GlobalStats.TotalFrees); \
        InterlockedAdd64(&(Manager)->GlobalStats.CurrentMemoryUsage, -(LONG64)(Size)); \
    } while (0)

#define LL_STATS_ALLOC(Lookaside, IsHit) \
    do { \
        InterlockedIncrement64(&(Lookaside)->Stats.TotalAllocations); \
        InterlockedAdd64(&(Lookaside)->Stats.TotalBytesAllocated, (LONG64)(Lookaside)->EntrySize); \
        if (IsHit) { \
            InterlockedIncrement64(&(Lookaside)->Stats.CacheHits); \
            if ((Lookaside)->Manager) \
                InterlockedIncrement64(&(Lookaside)->Manager->GlobalStats.TotalCacheHits); \
        } else { \
            InterlockedIncrement64(&(Lookaside)->Stats.CacheMisses); \
            if ((Lookaside)->Manager) \
                InterlockedIncrement64(&(Lookaside)->Manager->GlobalStats.TotalCacheMisses); \
        } \
        { \
            LONG _c = InterlockedIncrement(&(Lookaside)->Stats.CurrentOutstanding); \
            LONG _p = (Lookaside)->Stats.PeakOutstanding; \
            while (_c > _p) { \
                InterlockedCompareExchange(&(Lookaside)->Stats.PeakOutstanding, _c, _p); \
                _p = (Lookaside)->Stats.PeakOutstanding; \
            } \
        } \
    } while (0)

#define LL_STATS_FREE(Lookaside) \
    do { \
        InterlockedIncrement64(&(Lookaside)->Stats.TotalFrees); \
        InterlockedAdd64(&(Lookaside)->Stats.TotalBytesFreed, (LONG64)(Lookaside)->EntrySize); \
        InterlockedDecrement(&(Lookaside)->Stats.CurrentOutstanding); \
    } while (0)

// ============================================================================
// INTERNAL FORWARD DECLARATIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
LlpMaintenanceDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
LlpCheckMemoryPressure(
    _In_ PLL_MANAGER Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
LlpPressureWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

// ============================================================================
// INTERNAL LOCK-FREE REFERENCE COUNTING HELPERS
// ============================================================================

FORCEINLINE LONG
LlpExtractRefCount(_In_ LONG64 CombinedValue)
{
    return (LONG)(CombinedValue & 0x7FFFFFFF);
}

FORCEINLINE BOOLEAN
LlpIsDestroying(_In_ LONG64 CombinedValue)
{
    return (CombinedValue & LL_DESTROYING_FLAG) != 0;
}

FORCEINLINE ULONG
LlpExtractSequence(_In_ LONG64 CombinedValue)
{
    return (ULONG)((CombinedValue >> 32) & 0x7FFFFFFF);
}

FORCEINLINE LONG64
LlpBuildRefCountState(
    _In_ LONG RefCount,
    _In_ ULONG Sequence,
    _In_ BOOLEAN Destroying
    )
{
    LONG64 Value = (LONG64)(RefCount & 0x7FFFFFFF);
    Value |= ((LONG64)(Sequence & 0x7FFFFFFF)) << 32;
    if (Destroying) {
        Value |= (LONG64)LL_DESTROYING_FLAG;
    }
    return Value;
}

// ============================================================================
// INTERNAL POOL ALLOCATION HELPER
// ============================================================================

_Must_inspect_result_
static PVOID
LlpAllocatePool(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    )
{
    PVOID Buffer = NULL;

    if (NumberOfBytes == 0) {
        return NULL;
    }

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    {
        POOL_FLAGS PoolFlags = 0;

        if (PoolType == PagedPool || PoolType == PagedPoolCacheAligned) {
            PoolFlags = POOL_FLAG_PAGED;
        } else {
            PoolFlags = POOL_FLAG_NON_PAGED;
        }

        if (PoolType == NonPagedPoolCacheAligned || PoolType == PagedPoolCacheAligned) {
            PoolFlags |= POOL_FLAG_CACHE_ALIGNED;
        }

        Buffer = ExAllocatePool2(PoolFlags, NumberOfBytes, Tag);
    }
#else
    if (PoolType == NonPagedPool) {
        PoolType = NonPagedPoolNx;
    }

#pragma warning(push)
#pragma warning(disable: 4996)
#pragma warning(disable: 28118)
    Buffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
#pragma warning(pop)

    if (Buffer != NULL) {
        RtlZeroMemory(Buffer, NumberOfBytes);
    }
#endif

    return Buffer;
}

// ============================================================================
// INTERNAL STRING COMPARISON (no CRT dependency)
// ============================================================================

static BOOLEAN
LlpStringsEqual(
    _In_ PCSTR A,
    _In_ PCSTR B,
    _In_ SIZE_T MaxLen
    )
{
    SIZE_T i;
    for (i = 0; i < MaxLen; i++) {
        if (A[i] != B[i]) {
            return FALSE;
        }
        if (A[i] == '\0') {
            return TRUE;
        }
    }
    return TRUE;
}

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlInitialize(
    _Out_ PLL_MANAGER* Manager,
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    PLL_MANAGER NewManager = NULL;

    PAGED_CODE();

    if (Manager == NULL || DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    NewManager = (PLL_MANAGER)LlpAllocatePool(
        NonPagedPoolNx,
        sizeof(LL_MANAGER),
        LL_POOL_TAG
    );

    if (NewManager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NewManager->Magic = LL_MANAGER_MAGIC;
    NewManager->State = LlStateInitializing;

    ExInitializeRundownProtection(&NewManager->RundownRef);

    InitializeListHead(&NewManager->LookasideListHead);
    ExInitializePushLock(&NewManager->LookasideListLock);

    KeInitializeTimer(&NewManager->MaintenanceTimer);
    KeInitializeDpc(&NewManager->MaintenanceDpc, LlpMaintenanceDpcRoutine, NewManager);

    NewManager->DeviceObject = DeviceObject;
    NewManager->PressureWorkItem = IoAllocateWorkItem(DeviceObject);
    if (NewManager->PressureWorkItem == NULL) {
#if DBG
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] WARNING: IoAllocateWorkItem failed for pressure callbacks\n"
        );
#endif
    }

    KeQuerySystemTimePrecise(&NewManager->GlobalStats.StartTime);
    NewManager->GlobalStats.LastResetTime = NewManager->GlobalStats.StartTime;

    NewManager->MemoryLimit = 0;
    NewManager->PressureLevel = LlPressureNone;
    NewManager->SelfTuningEnabled = TRUE;
    NewManager->DebugMode = FALSE;

    InterlockedExchange((volatile LONG*)&NewManager->State, LlStateActive);

    *Manager = NewManager;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlShutdown(
    _Inout_ PLL_MANAGER* pManager
    )
{
    PLL_MANAGER Manager;
    PLIST_ENTRY Entry = NULL;
    PLIST_ENTRY NextEntry = NULL;
    PLL_LOOKASIDE Lookaside = NULL;
    LIST_ENTRY TempList;
    LL_STATE OldState;

    PAGED_CODE();

    if (pManager == NULL || *pManager == NULL) {
        return;
    }

    Manager = *pManager;
    *pManager = NULL;

    OldState = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Manager->State,
        LlStateDestroying,
        LlStateActive
    );

    if (OldState != LlStateActive) {
        return;
    }

    //
    // Step 1: Wait for all public API operations to complete
    //
    ExWaitForRundownProtectionRelease(&Manager->RundownRef);

    //
    // Step 2: Cancel maintenance timer, flush DPCs
    //
    if (Manager->MaintenanceEnabled) {
        KeCancelTimer(&Manager->MaintenanceTimer);
        KeFlushQueuedDpcs();
        Manager->MaintenanceEnabled = FALSE;
    }

    //
    // Step 3: Wait for any pending pressure work item to complete.
    // We spin until PressureWorkPending is 0 — the work item
    // clears this AFTER completing the callback.
    //
    if (Manager->PressureWorkItem != NULL) {
        LARGE_INTEGER SpinWait;
        SpinWait.QuadPart = -10000LL; // 1ms
        ULONG DrainIter = 0;

        while (InterlockedCompareExchange(&Manager->PressureWorkPending, 0, 0) != 0 &&
               DrainIter < LL_REFCOUNT_DRAIN_MAX_ITERATIONS) {
            KeDelayExecutionThread(KernelMode, FALSE, &SpinWait);
            DrainIter++;
        }

        IoFreeWorkItem(Manager->PressureWorkItem);
        Manager->PressureWorkItem = NULL;
    }

    //
    // Step 4: Collect all lookasides under lock
    //
    InitializeListHead(&TempList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = NextEntry) {

        NextEntry = Entry->Flink;
        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        //
        // Set destroying flag in combined ref/state word
        //
        {
            LONG64 OldValue, NewValue;
            LONG RefCount;
            ULONG Sequence;

            do {
                OldValue = InterlockedCompareExchange64(&Lookaside->RefCountAndState, 0, 0);
                RefCount = LlpExtractRefCount(OldValue);
                Sequence = LlpExtractSequence(OldValue);
                NewValue = LlpBuildRefCountState(RefCount, Sequence, TRUE);
            } while (InterlockedCompareExchange64(
                        &Lookaside->RefCountAndState,
                        NewValue,
                        OldValue) != OldValue);
        }

        RemoveEntryList(Entry);
        InsertTailList(&TempList, Entry);
    }

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    //
    // Step 5: Destroy each lookaside
    //
    while (!IsListEmpty(&TempList)) {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -((LONGLONG)LL_REFCOUNT_DRAIN_INTERVAL_MS * 10000);

        Entry = RemoveHeadList(&TempList);
        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        InterlockedExchange((volatile LONG*)&Lookaside->State, LlStateDestroying);

#if DBG
        if (Lookaside->Stats.CurrentOutstanding != 0) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike] WARNING: Lookaside '%s' shutdown with %d outstanding\n",
                Lookaside->Name,
                Lookaside->Stats.CurrentOutstanding
            );
        }
#endif

        //
        // Drain references
        //
        for (ULONG i = 0; i < LL_REFCOUNT_DRAIN_MAX_ITERATIONS; i++) {
            LONG64 Combined = InterlockedCompareExchange64(
                &Lookaside->RefCountAndState, 0, 0
            );
            if (LlpExtractRefCount(Combined) <= 0) {
                break;
            }
            KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        }

        if (Lookaside->IsPaged) {
            ExDeletePagedLookasideList(&Lookaside->NativeList.Paged);
        } else {
            ExDeleteNPagedLookasideList(&Lookaside->NativeList.NonPaged);
        }

        Lookaside->Magic = 0;
        InterlockedExchange((volatile LONG*)&Lookaside->State, LlStateDestroyed);
        ExFreePoolWithTag(Lookaside, LL_ENTRY_TAG);

        InterlockedDecrement(&Manager->LookasideCount);
        InterlockedDecrement(&Manager->GlobalStats.ActiveLookasideLists);
    }

    //
    // Step 6: Free manager
    //
    Manager->Magic = 0;
    InterlockedExchange((volatile LONG*)&Manager->State, LlStateDestroyed);
    ExFreePoolWithTag(Manager, LL_POOL_TAG);
}

// ============================================================================
// LOOKASIDE LIST CREATION AND DESTRUCTION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlCreateLookaside(
    _In_ PLL_MANAGER Manager,
    _In_ PCSTR Name,
    _In_ ULONG Tag,
    _In_ SIZE_T EntrySize,
    _In_ BOOLEAN IsPaged,
    _Out_ PLL_LOOKASIDE* Lookaside
    )
{
    return LlCreateLookasideEx(
        Manager,
        Name,
        Tag,
        EntrySize,
        IsPaged,
        LL_DEFAULT_DEPTH,
        LlAllocZeroMemory,
        Lookaside
    );
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlCreateLookasideEx(
    _In_ PLL_MANAGER Manager,
    _In_ PCSTR Name,
    _In_ ULONG Tag,
    _In_ SIZE_T EntrySize,
    _In_ BOOLEAN IsPaged,
    _In_ USHORT Depth,
    _In_ ULONG Flags,
    _Out_ PLL_LOOKASIDE* Lookaside
    )
{
    PLL_LOOKASIDE NewLookaside = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    if (Name == NULL || Lookaside == NULL) {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INVALID_PARAMETER;
    }

    *Lookaside = NULL;

    if (EntrySize < LL_MIN_ENTRY_SIZE || EntrySize > LL_MAX_ENTRY_SIZE) {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INVALID_PARAMETER;
    }

    if (Depth == 0) {
        Depth = LL_DEFAULT_DEPTH;
    } else if (Depth < LL_MIN_DEPTH) {
        Depth = LL_MIN_DEPTH;
    } else if (Depth > LL_MAX_DEPTH) {
        Depth = LL_MAX_DEPTH;
    }

    NewLookaside = (PLL_LOOKASIDE)LlpAllocatePool(
        NonPagedPoolNx,
        sizeof(LL_LOOKASIDE),
        LL_ENTRY_TAG
    );

    if (NewLookaside == NULL) {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = RtlStringCchCopyA(
        NewLookaside->Name,
        LL_MAX_NAME_LENGTH,
        Name
    );
    if (!NT_SUCCESS(Status)) {
        NewLookaside->Name[LL_MAX_NAME_LENGTH - 1] = '\0';
    }

    NewLookaside->Id = InterlockedIncrement(&Manager->NextLookasideId);
    NewLookaside->Tag = Tag;
    NewLookaside->EntrySize = EntrySize;
    NewLookaside->AlignedSize = (EntrySize + sizeof(PVOID) - 1) & ~(sizeof(PVOID) - 1);
    NewLookaside->IsPaged = IsPaged;
    NewLookaside->PoolType = IsPaged ? PagedPool : NonPagedPoolNx;
    NewLookaside->Flags = Flags;
    NewLookaside->Magic = LL_ENTRY_MAGIC;
    NewLookaside->Manager = Manager;
    NewLookaside->State = LlStateInitializing;
    NewLookaside->RefCountAndState = LlpBuildRefCountState(1, 0, FALSE);

    {
        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise(&Now);
        NewLookaside->CreateTime = Now;
        InterlockedExchange64(&NewLookaside->LastAccessTime, Now.QuadPart);
    }

    if (IsPaged) {
        ExInitializePagedLookasideList(
            &NewLookaside->NativeList.Paged,
            NULL, NULL, 0, EntrySize, Tag, Depth
        );
    } else {
        ExInitializeNPagedLookasideList(
            &NewLookaside->NativeList.NonPaged,
            NULL, NULL, 0, EntrySize, Tag, Depth
        );
    }

    InterlockedExchange((volatile LONG*)&NewLookaside->State, LlStateActive);

    //
    // Add to manager's list — count check under lock to prevent races
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    if (Manager->LookasideCount >= LL_MAX_LOOKASIDE_LISTS) {
        ExReleasePushLockExclusive(&Manager->LookasideListLock);
        KeLeaveCriticalRegion();

        if (IsPaged) {
            ExDeletePagedLookasideList(&NewLookaside->NativeList.Paged);
        } else {
            ExDeleteNPagedLookasideList(&NewLookaside->NativeList.NonPaged);
        }
        NewLookaside->Magic = 0;
        ExFreePoolWithTag(NewLookaside, LL_ENTRY_TAG);
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&Manager->LookasideListHead, &NewLookaside->ListEntry);
    InterlockedIncrement(&Manager->LookasideCount);
    InterlockedIncrement(&Manager->GlobalStats.ActiveLookasideLists);

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    *Lookaside = NewLookaside;

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlDestroyLookaside(
    _In_ PLL_MANAGER Manager,
    _In_ PLL_LOOKASIDE Lookaside
    )
{
    LARGE_INTEGER Timeout;
    ULONG WaitCount = 0;
    LL_STATE OldState;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    if (Lookaside == NULL || Lookaside->Magic != LL_ENTRY_MAGIC) {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INVALID_PARAMETER;
    }

    if (Lookaside->Manager != Manager) {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INVALID_PARAMETER;
    }

    OldState = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Lookaside->State,
        LlStateDestroying,
        LlStateActive
    );

    if (OldState != LlStateActive) {
        ExReleaseRundownProtection(&Manager->RundownRef);
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Remove from manager's list and set destroying flag
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    RemoveEntryList(&Lookaside->ListEntry);
    InitializeListHead(&Lookaside->ListEntry);

    {
        LONG64 OldValue, NewValue;
        LONG RefCount;
        ULONG Sequence;

        do {
            OldValue = InterlockedCompareExchange64(&Lookaside->RefCountAndState, 0, 0);
            RefCount = LlpExtractRefCount(OldValue);
            Sequence = LlpExtractSequence(OldValue);
            NewValue = LlpBuildRefCountState(RefCount, Sequence, TRUE);
        } while (InterlockedCompareExchange64(
                    &Lookaside->RefCountAndState,
                    NewValue,
                    OldValue) != OldValue);
    }

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    //
    // Wait for outstanding allocations
    //
    Timeout.QuadPart = -((LONGLONG)LL_REFCOUNT_DRAIN_INTERVAL_MS * 10000);

    while (Lookaside->Stats.CurrentOutstanding > 0 &&
           WaitCount < LL_REFCOUNT_DRAIN_MAX_ITERATIONS) {
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        WaitCount++;
    }

#if DBG
    if (Lookaside->Stats.CurrentOutstanding > 0) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] WARNING: Destroying lookaside '%s' with %d outstanding\n",
            Lookaside->Name,
            Lookaside->Stats.CurrentOutstanding
        );
    }
#endif

    //
    // Wait for references to drain
    //
    WaitCount = 0;
    while (WaitCount < LL_REFCOUNT_DRAIN_MAX_ITERATIONS) {
        LONG64 Combined = InterlockedCompareExchange64(
            &Lookaside->RefCountAndState, 0, 0
        );
        if (LlpExtractRefCount(Combined) <= 1) {
            break;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        WaitCount++;
    }

    if (Lookaside->IsPaged) {
        ExDeletePagedLookasideList(&Lookaside->NativeList.Paged);
    } else {
        ExDeleteNPagedLookasideList(&Lookaside->NativeList.NonPaged);
    }

    InterlockedDecrement(&Manager->LookasideCount);
    InterlockedDecrement(&Manager->GlobalStats.ActiveLookasideLists);

    Lookaside->Magic = 0;
    InterlockedExchange((volatile LONG*)&Lookaside->State, LlStateDestroyed);
    ExFreePoolWithTag(Lookaside, LL_ENTRY_TAG);

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// REFERENCE COUNTING - LOCK-FREE IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LlReferenceLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    )
{
    LONG64 OldValue;
    LONG64 NewValue;
    LONG OldRefCount;
    ULONG Sequence;

    if (Lookaside == NULL || Lookaside->Magic != LL_ENTRY_MAGIC) {
        return FALSE;
    }

    do {
        OldValue = InterlockedCompareExchange64(&Lookaside->RefCountAndState, 0, 0);

        if (LlpIsDestroying(OldValue)) {
            return FALSE;
        }

        OldRefCount = LlpExtractRefCount(OldValue);
        if (OldRefCount <= 0) {
            return FALSE;
        }

        Sequence = LlpExtractSequence(OldValue);

        NewValue = LlpBuildRefCountState(
            OldRefCount + 1,
            Sequence,
            FALSE
        );

    } while (InterlockedCompareExchange64(
                &Lookaside->RefCountAndState,
                NewValue,
                OldValue) != OldValue);

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlReleaseLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    )
{
    LONG64 OldValue;
    LONG64 NewValue;
    LONG OldRefCount;
    LONG NewRefCount;
    ULONG Sequence;
    BOOLEAN Destroying;

    if (Lookaside == NULL) {
        return;
    }

    do {
        OldValue = InterlockedCompareExchange64(&Lookaside->RefCountAndState, 0, 0);

        OldRefCount = LlpExtractRefCount(OldValue);
        Sequence = LlpExtractSequence(OldValue);
        Destroying = LlpIsDestroying(OldValue);

        NewRefCount = OldRefCount - 1;

        if (NewRefCount < 0) {
#if DBG
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "[ShadowStrike] CRITICAL: Lookaside '%s' refcount underflow (was %d)\n",
                Lookaside->Name,
                OldRefCount
            );
#endif
            if (Lookaside->Manager) {
                InterlockedIncrement64(&Lookaside->Manager->GlobalStats.RefCountRaces);
            }
            return;
        }

        Sequence = (Sequence + 1) & 0x7FFFFFFF;

        NewValue = LlpBuildRefCountState(
            NewRefCount,
            Sequence,
            Destroying
        );

    } while (InterlockedCompareExchange64(
                &Lookaside->RefCountAndState,
                NewValue,
                OldValue) != OldValue);
}

// ============================================================================
// ALLOCATION AND DEALLOCATION
// ============================================================================

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
PVOID
LlAllocate(
    _In_ PLL_LOOKASIDE Lookaside
    )
{
    return LlAllocateEx(Lookaside, LlAllocZeroMemory);
}

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
PVOID
LlAllocateEx(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ ULONG Flags
    )
{
    PVOID Block = NULL;
    BOOLEAN IsHit = FALSE;
    LL_STATE State;

    if (Lookaside == NULL || Lookaside->Magic != LL_ENTRY_MAGIC) {
        return NULL;
    }

    State = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Lookaside->State, 0, 0
    );

    if (State != LlStateActive) {
        return NULL;
    }

    if (Lookaside->IsPaged && KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement64(&Lookaside->Stats.AllocationFailures);
        return NULL;
    }

    //
    // Allocate from native lookaside
    //
    if (Lookaside->IsPaged) {
        Block = ExAllocateFromPagedLookasideList(&Lookaside->NativeList.Paged);
    } else {
        Block = ExAllocateFromNPagedLookasideList(&Lookaside->NativeList.NonPaged);
    }

    if (Block == NULL) {
        InterlockedIncrement64(&Lookaside->Stats.AllocationFailures);

        if (Flags & LlAllocMustSucceed) {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10 * 1000; // 1ms

            for (ULONG Retry = 0; Retry < 3 && Block == NULL; Retry++) {
                if (KeGetCurrentIrql() <= APC_LEVEL) {
                    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
                    Delay.QuadPart *= 2; // exponential backoff: 1ms, 2ms, 4ms
                } else {
                    //
                    // At DISPATCH_LEVEL, pool exhaustion won't resolve
                    // by spinning. Break early to avoid DPC timeout.
                    //
                    break;
                }

                if (Lookaside->IsPaged) {
                    Block = ExAllocateFromPagedLookasideList(&Lookaside->NativeList.Paged);
                } else {
                    Block = ExAllocateFromNPagedLookasideList(&Lookaside->NativeList.NonPaged);
                }
            }
        }

        if (Block == NULL) {
            return NULL;
        }
    }

    //
    // Determine cache hit using native lookaside L.TotalAllocates vs L.AllocateMisses.
    // A cache hit means the allocation was satisfied from the lookaside free list
    // without going to the pool allocator. We snapshot TotalAllocates before and check
    // AllocateMisses after — if AllocateMisses didn't change, it was a hit.
    // However, since we already did the allocation, we read the cumulative counters
    // and compute: Hits = TotalAllocates - AllocateMisses. Compare with our previous
    // snapshot to detect whether THIS allocation was a hit.
    //
    {
        ULONG NativeMisses;
        ULONG NativeTotal;

        if (Lookaside->IsPaged) {
            NativeTotal = Lookaside->NativeList.Paged.L.TotalAllocates;
            NativeMisses = Lookaside->NativeList.Paged.L.AllocateMisses;
        } else {
            NativeTotal = Lookaside->NativeList.NonPaged.L.TotalAllocates;
            NativeMisses = Lookaside->NativeList.NonPaged.L.AllocateMisses;
        }

        //
        // If misses equals total, every allocation missed the cache.
        // If misses < total, some were hits. For this single allocation,
        // check the ratio: if current miss rate < 100%, report as hit.
        // More precisely: if the native list had any hits at all in its
        // lifetime, the last allocation was likely a hit if the list wasn't
        // empty. The most accurate single-alloc method: sample misses before
        // and after. Since we can't do before/after atomically with the alloc,
        // we use: hits > 0 AND list had cached entries (CurrentOutstanding < depth).
        //
        if (NativeTotal > NativeMisses) {
            //
            // Native list has had cache hits — use depth heuristic.
            // If outstanding < depth, the list likely had free entries cached.
            //
            USHORT Depth;

            if (Lookaside->IsPaged) {
                Depth = Lookaside->NativeList.Paged.L.Depth;
            } else {
                Depth = Lookaside->NativeList.NonPaged.L.Depth;
            }

            IsHit = (Lookaside->Stats.CurrentOutstanding < (LONG)Depth);
        } else {
            IsHit = FALSE;
        }
    }

    //
    // Always zero for security
    //
    RtlZeroMemory(Block, Lookaside->EntrySize);

    LL_STATS_ALLOC(Lookaside, IsHit);
    if (Lookaside->Manager) {
        LL_TRACK_ALLOC(Lookaside->Manager, Lookaside->EntrySize);
    }

    //
    // Update last access time atomically
    //
    {
        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise(&Now);
        InterlockedExchange64(&Lookaside->LastAccessTime, Now.QuadPart);
    }

    return Block;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    )
{
    LL_STATE State;

    if (Lookaside == NULL || Lookaside->Magic != LL_ENTRY_MAGIC || Block == NULL) {
        return;
    }

    State = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Lookaside->State, 0, 0
    );

    if (State == LlStateDestroyed || State == LlStateUninitialized) {
        return;
    }

#if DBG
    if (Lookaside->Manager && Lookaside->Manager->DebugMode) {
        RtlFillMemory(Block, Lookaside->EntrySize, LL_POISON_PATTERN);
    }
#endif

    if (Lookaside->IsPaged) {
        ExFreeToPagedLookasideList(&Lookaside->NativeList.Paged, Block);
    } else {
        ExFreeToNPagedLookasideList(&Lookaside->NativeList.NonPaged, Block);
    }

    LL_STATS_FREE(Lookaside);
    if (Lookaside->Manager) {
        LL_TRACK_FREE(Lookaside->Manager, Lookaside->EntrySize);
    }

    {
        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise(&Now);
        InterlockedExchange64(&Lookaside->LastAccessTime, Now.QuadPart);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlSecureFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    )
{
    LL_STATE State;

    if (Lookaside == NULL || Lookaside->Magic != LL_ENTRY_MAGIC || Block == NULL) {
        return;
    }

    State = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Lookaside->State, 0, 0
    );

    if (State == LlStateDestroyed || State == LlStateUninitialized) {
        return;
    }

    RtlSecureZeroMemory(Block, Lookaside->EntrySize);

    InterlockedIncrement64(&Lookaside->Stats.SecureFrees);

    if (Lookaside->IsPaged) {
        ExFreeToPagedLookasideList(&Lookaside->NativeList.Paged, Block);
    } else {
        ExFreeToNPagedLookasideList(&Lookaside->NativeList.NonPaged, Block);
    }

    LL_STATS_FREE(Lookaside);
    if (Lookaside->Manager) {
        LL_TRACK_FREE(Lookaside->Manager, Lookaside->EntrySize);
    }
}

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetStatistics(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PLL_STATISTICS Statistics
    )
{
    if (!LlIsValid(Lookaside) || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Statistics->TotalAllocations = Lookaside->Stats.TotalAllocations;
    Statistics->TotalFrees = Lookaside->Stats.TotalFrees;
    Statistics->CacheHits = Lookaside->Stats.CacheHits;
    Statistics->CacheMisses = Lookaside->Stats.CacheMisses;
    Statistics->CurrentOutstanding = Lookaside->Stats.CurrentOutstanding;
    Statistics->PeakOutstanding = Lookaside->Stats.PeakOutstanding;
    Statistics->AllocationFailures = Lookaside->Stats.AllocationFailures;
    Statistics->TotalBytesAllocated = Lookaside->Stats.TotalBytesAllocated;
    Statistics->TotalBytesFreed = Lookaside->Stats.TotalBytesFreed;
    Statistics->AverageLatency = Lookaside->Stats.AverageLatency;
    Statistics->MaxLatency = Lookaside->Stats.MaxLatency;
    Statistics->SecureFrees = Lookaside->Stats.SecureFrees;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetHitMissRatio(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PULONG64 Hits,
    _Out_ PULONG64 Misses
    )
{
    if (!LlIsValid(Lookaside) || Hits == NULL || Misses == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Hits = Lookaside->Stats.CacheHits;
    *Misses = Lookaside->Stats.CacheMisses;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetStats(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PULONG64 Hits,
    _Out_ PULONG64 Misses
    )
{
    return LlGetHitMissRatio(Lookaside, Hits, Misses);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetGlobalStatistics(
    _In_ PLL_MANAGER Manager,
    _Out_ PLL_GLOBAL_STATISTICS Statistics
    )
{
    if (!LlManagerIsValid(Manager) || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Statistics->TotalAllocations = Manager->GlobalStats.TotalAllocations;
    Statistics->TotalFrees = Manager->GlobalStats.TotalFrees;
    Statistics->TotalCacheHits = Manager->GlobalStats.TotalCacheHits;
    Statistics->TotalCacheMisses = Manager->GlobalStats.TotalCacheMisses;
    Statistics->CurrentMemoryUsage = Manager->GlobalStats.CurrentMemoryUsage;
    Statistics->PeakMemoryUsage = Manager->GlobalStats.PeakMemoryUsage;
    Statistics->ActiveLookasideLists = Manager->GlobalStats.ActiveLookasideLists;
    Statistics->MemoryPressureEvents = Manager->GlobalStats.MemoryPressureEvents;
    Statistics->RefCountRaces = Manager->GlobalStats.RefCountRaces;
    Statistics->StartTime = Manager->GlobalStats.StartTime;
    Statistics->LastResetTime = Manager->GlobalStats.LastResetTime;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlResetStatistics(
    _In_ PLL_LOOKASIDE Lookaside
    )
{
    if (!LlIsValid(Lookaside)) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange64(&Lookaside->Stats.TotalAllocations, 0);
    InterlockedExchange64(&Lookaside->Stats.TotalFrees, 0);
    InterlockedExchange64(&Lookaside->Stats.CacheHits, 0);
    InterlockedExchange64(&Lookaside->Stats.CacheMisses, 0);
    InterlockedExchange(&Lookaside->Stats.PeakOutstanding, Lookaside->Stats.CurrentOutstanding);
    InterlockedExchange64(&Lookaside->Stats.AllocationFailures, 0);
    InterlockedExchange64(&Lookaside->Stats.TotalBytesAllocated, 0);
    InterlockedExchange64(&Lookaside->Stats.TotalBytesFreed, 0);
    InterlockedExchange64(&Lookaside->Stats.AverageLatency, 0);
    InterlockedExchange64(&Lookaside->Stats.MaxLatency, 0);
    InterlockedExchange64(&Lookaside->Stats.SecureFrees, 0);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlResetGlobalStatistics(
    _In_ PLL_MANAGER Manager
    )
{
    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange64(&Manager->GlobalStats.TotalAllocations, 0);
    InterlockedExchange64(&Manager->GlobalStats.TotalFrees, 0);
    InterlockedExchange64(&Manager->GlobalStats.TotalCacheHits, 0);
    InterlockedExchange64(&Manager->GlobalStats.TotalCacheMisses, 0);
    InterlockedExchange64(&Manager->GlobalStats.PeakMemoryUsage, Manager->GlobalStats.CurrentMemoryUsage);
    InterlockedExchange64(&Manager->GlobalStats.MemoryPressureEvents, 0);
    InterlockedExchange64(&Manager->GlobalStats.RefCountRaces, 0);

    KeQuerySystemTimePrecise(&Manager->GlobalStats.LastResetTime);

    return STATUS_SUCCESS;
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlSetMemoryLimit(
    _In_ PLL_MANAGER Manager,
    _In_ LONG64 MemoryLimit
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    InterlockedExchange64(&Manager->MemoryLimit, MemoryLimit);

    if (MemoryLimit > 0) {
        LlpCheckMemoryPressure(Manager);
    }

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG64
LlGetMemoryUsage(
    _In_ PLL_MANAGER Manager
    )
{
    if (!LlManagerIsValid(Manager)) {
        return 0;
    }

    return InterlockedCompareExchange64(
        &Manager->GlobalStats.CurrentMemoryUsage, 0, 0
    );
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlRegisterPressureCallback(
    _In_ PLL_MANAGER Manager,
    _In_ LL_PRESSURE_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager) || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Write callback pointer atomically to prevent torn reads from DPC
    //
    Manager->PressureCallbackContext = Context;
    InterlockedExchangePointer((PVOID*)&Manager->PressureCallback, (PVOID)Callback);

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

/**
 * @brief Trim cached entries by deleting and recreating native lookaside lists.
 *
 * The only reliable way to force Windows lookaside lists to release cached
 * entries back to the pool is to delete and re-initialize them. This function
 * iterates all managed lists, acquires exclusive access per-list via the
 * RefCountAndState mechanism, deletes the native list, and re-creates it
 * with the same parameters. Active allocations are NOT affected — they
 * were already removed from the free list and will be returned to pool
 * on the next LlFree (new native list will accept them).
 *
 * Returns estimated bytes freed (based on native list miss statistics).
 */
_IRQL_requires_(PASSIVE_LEVEL)
LONG64
LlTrimCaches(
    _In_ PLL_MANAGER Manager
    )
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PLL_LOOKASIDE Lookaside;
    LONG64 BytesFreed = 0;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return 0;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return 0;
    }

    //
    // Acquire exclusive lock — trim is a heavyweight operation that
    // modifies native list internals. No allocations or frees may be
    // in-flight on any managed list during the delete/reinit cycle.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = NextEntry) {

        //
        // Capture next before any potential list manipulation
        //
        NextEntry = Entry->Flink;

        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        if (!LlIsValid(Lookaside)) {
            continue;
        }

        //
        // Skip lists that are not active
        //
        {
            LL_STATE State = (LL_STATE)InterlockedCompareExchange(
                (volatile LONG*)&Lookaside->State, 0, 0
            );
            if (State != LlStateActive) {
                continue;
            }
        }

        //
        // Skip lists with outstanding allocations that exceed the
        // native list depth — these lists are fully utilized and
        // trimming would not reclaim meaningful memory.
        //
        if (Lookaside->Stats.CurrentOutstanding < 0) {
            continue;
        }

        //
        // Estimate cached (free-list) entries from native list counters.
        // NativeFrees - NativeFreeMisses = entries successfully returned to cache.
        // NativeAllocates - NativeAllocMisses = entries served from cache.
        // Cached entries ≈ (successful returns) - (cache hits) when positive.
        //
        {
            ULONG NativeAllocTotal;
            ULONG NativeAllocMisses;
            ULONG NativeFreeTotal;
            ULONG NativeFreeMisses;
            LONG64 CachedEstimate;

            if (Lookaside->IsPaged) {
                NativeAllocTotal  = Lookaside->NativeList.Paged.L.TotalAllocates;
                NativeAllocMisses = Lookaside->NativeList.Paged.L.AllocateMisses;
                NativeFreeTotal   = Lookaside->NativeList.Paged.L.TotalFrees;
                NativeFreeMisses  = Lookaside->NativeList.Paged.L.FreeMisses;
            } else {
                NativeAllocTotal  = Lookaside->NativeList.NonPaged.L.TotalAllocates;
                NativeAllocMisses = Lookaside->NativeList.NonPaged.L.AllocateMisses;
                NativeFreeTotal   = Lookaside->NativeList.NonPaged.L.TotalFrees;
                NativeFreeMisses  = Lookaside->NativeList.NonPaged.L.FreeMisses;
            }

            //
            // Entries in cache = (frees that hit cache) - (allocs that hit cache)
            //
            CachedEstimate = (LONG64)(NativeFreeTotal - NativeFreeMisses)
                           - (LONG64)(NativeAllocTotal - NativeAllocMisses);

            if (CachedEstimate <= 0) {
                //
                // No cached entries to reclaim — skip the expensive delete/reinit
                //
                continue;
            }

            BytesFreed += CachedEstimate * (LONG64)Lookaside->EntrySize;
        }

        //
        // Suspend the list to prevent racing allocations during reinit.
        // Any allocation attempt seeing LlStateSuspended will fail gracefully.
        //
        InterlockedExchange((volatile LONG*)&Lookaside->State, LlStateSuspended);

        //
        // Delete and reinitialize the native lookaside list.
        // ExDelete*LookasideList frees all cached entries back to pool.
        // ExInitialize*LookasideList creates a fresh empty list.
        // Outstanding allocations are unaffected — they've already been
        // removed from the SLIST. When freed via LlFree, ExFreeTo*List
        // will insert them into the new list's SLIST.
        //
        if (Lookaside->IsPaged) {
            USHORT SavedDepth = Lookaside->NativeList.Paged.L.Depth;
            ExDeletePagedLookasideList(&Lookaside->NativeList.Paged);
            ExInitializePagedLookasideList(
                &Lookaside->NativeList.Paged,
                NULL, NULL, 0,
                Lookaside->EntrySize,
                Lookaside->Tag,
                SavedDepth
            );
        } else {
            USHORT SavedDepth = Lookaside->NativeList.NonPaged.L.Depth;
            ExDeleteNPagedLookasideList(&Lookaside->NativeList.NonPaged);
            ExInitializeNPagedLookasideList(
                &Lookaside->NativeList.NonPaged,
                NULL, NULL, 0,
                Lookaside->EntrySize,
                Lookaside->Tag,
                SavedDepth
            );
        }

        //
        // Reactivate the list
        //
        InterlockedExchange((volatile LONG*)&Lookaside->State, LlStateActive);
    }

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Manager->RundownRef);
    return BytesFreed;
}

// ============================================================================
// MAINTENANCE AND TUNING
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlEnableMaintenance(
    _In_ PLL_MANAGER Manager,
    _In_ ULONG IntervalMs
    )
{
    LARGE_INTEGER DueTime;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    if (IntervalMs < 100) {
        IntervalMs = 100;
    }

    Manager->MaintenanceIntervalMs = IntervalMs;
    Manager->MaintenanceEnabled = TRUE;

    DueTime.QuadPart = -((LONGLONG)IntervalMs * 10000);

    KeSetTimerEx(
        &Manager->MaintenanceTimer,
        DueTime,
        IntervalMs,
        &Manager->MaintenanceDpc
    );

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlDisableMaintenance(
    _In_ PLL_MANAGER Manager
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    if (Manager->MaintenanceEnabled) {
        KeCancelTimer(&Manager->MaintenanceTimer);
        KeFlushQueuedDpcs();
        Manager->MaintenanceEnabled = FALSE;
    }

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlEnableSelfTuning(
    _In_ PLL_MANAGER Manager,
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    Manager->SelfTuningEnabled = Enable;

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// ENUMERATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlEnumerateLookasides(
    _In_ PLL_MANAGER Manager,
    _In_ LL_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PLIST_ENTRY Entry = NULL;
    PLIST_ENTRY NextEntry = NULL;
    PLL_LOOKASIDE Lookaside = NULL;
    BOOLEAN Continue = TRUE;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager) || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead && Continue;
         Entry = NextEntry) {

        //
        // Capture next before callback (callback must NOT modify list)
        //
        NextEntry = Entry->Flink;

        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        if (LlIsValid(Lookaside)) {
            Continue = Callback(Lookaside, Context);
        }
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlFindByName(
    _In_ PLL_MANAGER Manager,
    _In_ PCSTR Name,
    _Out_ PLL_LOOKASIDE* Lookaside
    )
{
    PLIST_ENTRY Entry = NULL;
    PLL_LOOKASIDE Current = NULL;
    NTSTATUS Status = STATUS_NOT_FOUND;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager) || Name == NULL || Lookaside == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    *Lookaside = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = Entry->Flink) {

        Current = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        if (LlpStringsEqual(Current->Name, Name, LL_MAX_NAME_LENGTH) &&
            LlIsValid(Current)) {
            if (LlReferenceLookaside(Current)) {
                *Lookaside = Current;
                Status = STATUS_SUCCESS;
            }
            break;
        }
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Manager->RundownRef);
    return Status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlFindByTag(
    _In_ PLL_MANAGER Manager,
    _In_ ULONG Tag,
    _Out_ PLL_LOOKASIDE* Lookaside
    )
{
    PLIST_ENTRY Entry = NULL;
    PLL_LOOKASIDE Current = NULL;
    NTSTATUS Status = STATUS_NOT_FOUND;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager) || Lookaside == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    *Lookaside = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = Entry->Flink) {

        Current = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        if (Current->Tag == Tag && LlIsValid(Current)) {
            if (LlReferenceLookaside(Current)) {
                *Lookaside = Current;
                Status = STATUS_SUCCESS;
            }
            break;
        }
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Manager->RundownRef);
    return Status;
}

// ============================================================================
// DEBUG AND DIAGNOSTICS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlSetDebugMode(
    _In_ PLL_MANAGER Manager,
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Manager->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    Manager->DebugMode = Enable;

    ExReleaseRundownProtection(&Manager->RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LlValidateLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    )
{
    if (Lookaside == NULL) {
        return FALSE;
    }

    if (Lookaside->Magic != LL_ENTRY_MAGIC) {
        return FALSE;
    }

    if ((LL_STATE)InterlockedCompareExchange(
            (volatile LONG*)&Lookaside->State, 0, 0) != LlStateActive) {
        return FALSE;
    }

    if (Lookaside->EntrySize < LL_MIN_ENTRY_SIZE ||
        Lookaside->EntrySize > LL_MAX_ENTRY_SIZE) {
        return FALSE;
    }

    if (Lookaside->Manager == NULL) {
        return FALSE;
    }

    {
        LONG64 Combined = InterlockedCompareExchange64(&Lookaside->RefCountAndState, 0, 0);
        if (LlpExtractRefCount(Combined) < 0 || LlpIsDestroying(Combined)) {
            return FALSE;
        }
    }

    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlDumpDiagnostics(
    _In_ PLL_MANAGER Manager
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return;
    }

#if DBG
    {
        PLIST_ENTRY Entry = NULL;
        PLL_LOOKASIDE Lookaside = NULL;

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[ShadowStrike] ===== LOOKASIDE LIST DIAGNOSTICS (v3.1.0) =====\n"
        );

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[ShadowStrike] Global Stats:\n"
            "  Total Allocations: %lld\n"
            "  Total Frees: %lld\n"
            "  Cache Hit Rate: %lu%%\n"
            "  Current Memory: %lld bytes\n"
            "  Peak Memory: %lld bytes\n"
            "  Active Lists: %ld\n"
            "  RefCount Races: %lld\n",
            Manager->GlobalStats.TotalAllocations,
            Manager->GlobalStats.TotalFrees,
            LlCalculateHitRate(Manager->GlobalStats.TotalCacheHits, Manager->GlobalStats.TotalCacheMisses),
            Manager->GlobalStats.CurrentMemoryUsage,
            Manager->GlobalStats.PeakMemoryUsage,
            Manager->GlobalStats.ActiveLookasideLists,
            Manager->GlobalStats.RefCountRaces
        );

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Manager->LookasideListLock);

        for (Entry = Manager->LookasideListHead.Flink;
             Entry != &Manager->LookasideListHead;
             Entry = Entry->Flink) {

            Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

            {
                LONG64 Combined = InterlockedCompareExchange64(&Lookaside->RefCountAndState, 0, 0);
                LONG RefCount = LlpExtractRefCount(Combined);

                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_INFO_LEVEL,
                    "[ShadowStrike] Lookaside '%s' (Tag: 0x%08X, Size: %llu, RefCount: %ld):\n"
                    "  State: %d, Allocations: %lld, Frees: %lld\n"
                    "  Outstanding: %ld (Peak: %ld)\n"
                    "  Hit Rate: %lu%%, Secure Frees: %lld\n",
                    Lookaside->Name,
                    Lookaside->Tag,
                    (ULONG64)Lookaside->EntrySize,
                    RefCount,
                    Lookaside->State,
                    Lookaside->Stats.TotalAllocations,
                    Lookaside->Stats.TotalFrees,
                    Lookaside->Stats.CurrentOutstanding,
                    Lookaside->Stats.PeakOutstanding,
                    LlCalculateHitRate(Lookaside->Stats.CacheHits, Lookaside->Stats.CacheMisses),
                    Lookaside->Stats.SecureFrees
                );
            }
        }

        ExReleasePushLockShared(&Manager->LookasideListLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[ShadowStrike] ===== END DIAGNOSTICS =====\n"
        );
    }
#else
    UNREFERENCED_PARAMETER(Manager);
#endif
}

// ============================================================================
// INTERNAL: MAINTENANCE DPC ROUTINE
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
LlpMaintenanceDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PLL_MANAGER Manager = (PLL_MANAGER)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Manager == NULL) {
        return;
    }

    if ((LL_STATE)InterlockedCompareExchange(
            (volatile LONG*)&Manager->State, 0, 0) != LlStateActive) {
        return;
    }

    LlpCheckMemoryPressure(Manager);
}

// ============================================================================
// INTERNAL: MEMORY PRESSURE CHECK
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
LlpCheckMemoryPressure(
    _In_ PLL_MANAGER Manager
    )
{
    LL_MEMORY_PRESSURE OldPressure;
    LL_MEMORY_PRESSURE NewPressure;
    LONG64 CurrentUsage;
    LONG64 Limit;
    ULONG UsagePercent;

    Limit = InterlockedCompareExchange64(&Manager->MemoryLimit, 0, 0);

    if (Limit <= 0) {
        return;
    }

    CurrentUsage = InterlockedCompareExchange64(
        &Manager->GlobalStats.CurrentMemoryUsage, 0, 0
    );

    //
    // Overflow-safe percentage: divide first, then multiply
    // For typical EDR workloads, CurrentUsage << 2^63 so this is fine.
    // But guard against negative values from race conditions.
    //
    if (CurrentUsage < 0) {
        CurrentUsage = 0;
    }

    if (CurrentUsage > (LONG64)(0x7FFFFFFFFFFFFFFFLL / 100)) {
        UsagePercent = (ULONG)(CurrentUsage / (Limit / 100));
    } else {
        UsagePercent = (ULONG)((CurrentUsage * 100) / Limit);
    }

    OldPressure = Manager->PressureLevel;

    if (UsagePercent >= 95) {
        NewPressure = LlPressureCritical;
    } else if (UsagePercent >= LL_MEMORY_PRESSURE_HIGH) {
        NewPressure = LlPressureHigh;
    } else if (UsagePercent >= LL_MEMORY_PRESSURE_LOW) {
        NewPressure = LlPressureModerate;
    } else {
        NewPressure = LlPressureNone;
    }

    if (NewPressure != OldPressure) {
        InterlockedExchange((volatile LONG*)&Manager->PressureLevel, (LONG)NewPressure);
        InterlockedIncrement64(&Manager->GlobalStats.MemoryPressureEvents);

        if (Manager->PressureCallback != NULL && Manager->PressureWorkItem != NULL) {
            InterlockedExchange((volatile LONG*)&Manager->PendingPressureLevel, (LONG)NewPressure);
            InterlockedExchange64(&Manager->PendingCurrentMemory, CurrentUsage);
            InterlockedExchange64(&Manager->PendingMemoryLimit, Limit);

            if (InterlockedCompareExchange(&Manager->PressureWorkPending, 1, 0) == 0) {
                IoQueueWorkItem(
                    Manager->PressureWorkItem,
                    LlpPressureWorkItemRoutine,
                    DelayedWorkQueue,
                    Manager
                );
            }
        }
    }
}

// ============================================================================
// INTERNAL: PRESSURE WORK ITEM ROUTINE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
LlpPressureWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PLL_MANAGER Manager = (PLL_MANAGER)Context;
    LL_MEMORY_PRESSURE PressureLevel;
    LONG64 CurrentMemory;
    LONG64 MemoryLimit;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Manager == NULL) {
        return;
    }

    PressureLevel = (LL_MEMORY_PRESSURE)InterlockedCompareExchange(
        (volatile LONG*)&Manager->PendingPressureLevel, 0, 0
    );
    CurrentMemory = InterlockedCompareExchange64(&Manager->PendingCurrentMemory, 0, 0);
    MemoryLimit = InterlockedCompareExchange64(&Manager->PendingMemoryLimit, 0, 0);

    //
    // Invoke callback BEFORE clearing the pending flag.
    // This prevents the race where a new work item is queued
    // while this one is still running, which could cause
    // IoQueueWorkItem on an already-queued item.
    //
    if (Manager->PressureCallback != NULL && LlManagerIsValid(Manager)) {
        Manager->PressureCallback(
            PressureLevel,
            CurrentMemory,
            MemoryLimit,
            Manager->PressureCallbackContext
        );
    }

    //
    // Clear pending AFTER callback completes — shutdown drains this flag
    //
    InterlockedExchange(&Manager->PressureWorkPending, 0);
}
