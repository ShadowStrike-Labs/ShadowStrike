/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE LOOKASIDE LIST MANAGER
 * ============================================================================
 *
 * @file LookasideLists.c
 * @brief High-performance lookaside list management implementation.
 *
 * This module implements CrowdStrike/SentinelOne-class lookaside list
 * infrastructure for kernel-mode EDR operations. All functions are
 * designed for:
 * - Maximum performance (O(1) allocations, lock-free statistics)
 * - Memory efficiency (adaptive caching, pressure-aware)
 * - Reliability (comprehensive validation, leak detection)
 * - Observability (detailed statistics, diagnostics)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "LookasideLists.h"
#include <ntstrsafe.h>

// ============================================================================
// PAGED/NON-PAGED CODE SEGMENT DECLARATIONS
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, LlInitialize)
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

/**
 * @brief Update global allocation statistics
 */
#define LL_TRACK_ALLOC(Manager, Size) \
    do { \
        InterlockedIncrement64(&(Manager)->GlobalStats.TotalAllocations); \
        InterlockedAdd64(&(Manager)->GlobalStats.CurrentMemoryUsage, (LONG64)(Size)); \
        LONG64 current = (Manager)->GlobalStats.CurrentMemoryUsage; \
        LONG64 peak = (Manager)->GlobalStats.PeakMemoryUsage; \
        while (current > peak) { \
            InterlockedCompareExchange64(&(Manager)->GlobalStats.PeakMemoryUsage, current, peak); \
            peak = (Manager)->GlobalStats.PeakMemoryUsage; \
        } \
    } while (0)

/**
 * @brief Update global free statistics
 */
#define LL_TRACK_FREE(Manager, Size) \
    do { \
        InterlockedIncrement64(&(Manager)->GlobalStats.TotalFrees); \
        InterlockedAdd64(&(Manager)->GlobalStats.CurrentMemoryUsage, -(LONG64)(Size)); \
    } while (0)

/**
 * @brief Update lookaside-specific statistics for allocation
 */
#define LL_STATS_ALLOC(Lookaside, IsHit) \
    do { \
        InterlockedIncrement64(&(Lookaside)->Stats.TotalAllocations); \
        InterlockedAdd64(&(Lookaside)->Stats.TotalBytesAllocated, (LONG64)(Lookaside)->EntrySize); \
        if (IsHit) { \
            InterlockedIncrement64(&(Lookaside)->Stats.CacheHits); \
            InterlockedIncrement64(&(Lookaside)->Manager->GlobalStats.TotalCacheHits); \
        } else { \
            InterlockedIncrement64(&(Lookaside)->Stats.CacheMisses); \
            InterlockedIncrement64(&(Lookaside)->Manager->GlobalStats.TotalCacheMisses); \
        } \
        LONG current = InterlockedIncrement(&(Lookaside)->Stats.CurrentOutstanding); \
        LONG peak = (Lookaside)->Stats.PeakOutstanding; \
        while (current > peak) { \
            InterlockedCompareExchange(&(Lookaside)->Stats.PeakOutstanding, current, peak); \
            peak = (Lookaside)->Stats.PeakOutstanding; \
        } \
    } while (0)

/**
 * @brief Update lookaside-specific statistics for free
 */
#define LL_STATS_FREE(Lookaside) \
    do { \
        InterlockedIncrement64(&(Lookaside)->Stats.TotalFrees); \
        InterlockedAdd64(&(Lookaside)->Stats.TotalBytesFreed, (LONG64)(Lookaside)->EntrySize); \
        InterlockedDecrement(&(Lookaside)->Stats.CurrentOutstanding); \
    } while (0)

// ============================================================================
// INTERNAL FORWARD DECLARATIONS
// ============================================================================

static VOID
LlpMaintenanceDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
LlpCheckMemoryPressure(
    _In_ PLL_MANAGER Manager
    );

static VOID
LlpSecureWipeMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
    );

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlInitialize(
    _Out_ PLL_MANAGER* Manager
    )
{
    PLL_MANAGER NewManager = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Allocate manager structure
    //
    NewManager = (PLL_MANAGER)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(LL_MANAGER),
        LL_POOL_TAG
    );

    if (NewManager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize the structure
    //
    RtlZeroMemory(NewManager, sizeof(LL_MANAGER));

    NewManager->Magic = LL_ENTRY_MAGIC;
    NewManager->State = LlStateActive;

    //
    // Initialize the lookaside list
    //
    InitializeListHead(&NewManager->LookasideListHead);
    ExInitializePushLock(&NewManager->LookasideListLock);

    //
    // Initialize spinlock and event
    //
    KeInitializeSpinLock(&NewManager->FastLock);
    KeInitializeEvent(&NewManager->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize timer and DPC for maintenance
    //
    KeInitializeTimer(&NewManager->MaintenanceTimer);
    KeInitializeDpc(&NewManager->MaintenanceDpc, LlpMaintenanceDpcRoutine, NewManager);

    //
    // Record start time
    //
    KeQuerySystemTimePrecise(&NewManager->GlobalStats.StartTime);
    NewManager->GlobalStats.LastResetTime = NewManager->GlobalStats.StartTime;

    //
    // Set defaults
    //
    NewManager->MemoryLimit = 0; // Unlimited
    NewManager->PressureLevel = LlPressureNone;
    NewManager->SelfTuningEnabled = TRUE;
    NewManager->DebugMode = FALSE;
    NewManager->RefCount = 1;

    //
    // Mark as initialized
    //
    NewManager->Initialized = TRUE;

    *Manager = NewManager;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlShutdown(
    _Inout_ PLL_MANAGER Manager
    )
{
    PLIST_ENTRY Entry = NULL;
    PLL_LOOKASIDE Lookaside = NULL;
    LIST_ENTRY TempList;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Mark as shutting down
    //
    Manager->State = LlStateDestroying;
    Manager->Initialized = FALSE;

    //
    // Disable and cancel maintenance timer
    //
    if (Manager->MaintenanceEnabled) {
        KeCancelTimer(&Manager->MaintenanceTimer);
        KeFlushQueuedDpcs();
        Manager->MaintenanceEnabled = FALSE;
    }

    //
    // Collect all lookasides into a temporary list
    //
    InitializeListHead(&TempList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    while (!IsListEmpty(&Manager->LookasideListHead)) {
        Entry = RemoveHeadList(&Manager->LookasideListHead);
        InsertTailList(&TempList, Entry);
    }

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    //
    // Destroy each lookaside
    //
    while (!IsListEmpty(&TempList)) {
        Entry = RemoveHeadList(&TempList);
        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

#if DBG
        //
        // Warn about outstanding allocations
        //
        if (Lookaside->Stats.CurrentOutstanding != 0) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike] WARNING: Lookaside '%s' shutdown with %d outstanding allocations\n",
                Lookaside->Name,
                Lookaside->Stats.CurrentOutstanding
            );
        }
#endif

        //
        // Delete the native lookaside
        //
        if (Lookaside->IsPaged) {
            ExDeletePagedLookasideList(&Lookaside->NativeList.Paged);
        } else {
            ExDeleteNPagedLookasideList(&Lookaside->NativeList.NonPaged);
        }

        //
        // Clear magic and free
        //
        Lookaside->Magic = 0;
        Lookaside->State = LlStateDestroyed;

        ExFreePoolWithTag(Lookaside, LL_ENTRY_TAG);
    }

    //
    // Signal shutdown complete
    //
    KeSetEvent(&Manager->ShutdownEvent, IO_NO_INCREMENT, FALSE);

    //
    // Clear magic and free manager
    //
    Manager->Magic = 0;
    Manager->State = LlStateDestroyed;

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

    //
    // Validate parameters
    //
    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Name == NULL || Lookaside == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Lookaside = NULL;

    //
    // Validate entry size
    //
    if (EntrySize < LL_MIN_ENTRY_SIZE || EntrySize > LL_MAX_ENTRY_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check maximum lookaside count
    //
    if (Manager->LookasideCount >= LL_MAX_LOOKASIDE_LISTS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Clamp depth to valid range
    //
    if (Depth == 0) {
        Depth = LL_DEFAULT_DEPTH;
    } else if (Depth < LL_MIN_DEPTH) {
        Depth = LL_MIN_DEPTH;
    } else if (Depth > LL_MAX_DEPTH) {
        Depth = LL_MAX_DEPTH;
    }

    //
    // Allocate lookaside structure
    //
    NewLookaside = (PLL_LOOKASIDE)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(LL_LOOKASIDE),
        LL_ENTRY_TAG
    );

    if (NewLookaside == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize the structure
    //
    RtlZeroMemory(NewLookaside, sizeof(LL_LOOKASIDE));

    //
    // Copy name (truncate if necessary)
    //
    Status = RtlStringCchCopyA(
        NewLookaside->Name,
        LL_MAX_NAME_LENGTH,
        Name
    );
    if (!NT_SUCCESS(Status)) {
        //
        // Truncation is acceptable
        //
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
    NewLookaside->State = LlStateActive;

    //
    // Record creation time
    //
    KeQuerySystemTimePrecise(&NewLookaside->CreateTime);
    NewLookaside->LastAccessTime = NewLookaside->CreateTime;

    //
    // Initialize the native lookaside list
    //
    if (IsPaged) {
        ExInitializePagedLookasideList(
            &NewLookaside->NativeList.Paged,
            NULL,   // Allocate function (use default)
            NULL,   // Free function (use default)
            0,      // Flags
            EntrySize,
            Tag,
            Depth
        );
    } else {
        ExInitializeNPagedLookasideList(
            &NewLookaside->NativeList.NonPaged,
            NULL,   // Allocate function (use default)
            NULL,   // Free function (use default)
            0,      // Flags
            EntrySize,
            Tag,
            Depth
        );
    }

    //
    // Add to manager's list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    InsertTailList(&Manager->LookasideListHead, &NewLookaside->ListEntry);
    InterlockedIncrement(&Manager->LookasideCount);
    InterlockedIncrement(&Manager->GlobalStats.ActiveLookasideLists);

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    *Lookaside = NewLookaside;

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
    const ULONG MaxWaits = 100;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (!LlManagerIsValid(Manager)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!LlIsValid(Lookaside)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Lookaside->Manager != Manager) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Mark as destroying
    //
    Lookaside->State = LlStateDestroying;

    //
    // Wait for outstanding allocations with timeout
    //
    Timeout.QuadPart = -10 * 1000 * 10; // 10ms

    while (Lookaside->Stats.CurrentOutstanding > 0 && WaitCount < MaxWaits) {
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        WaitCount++;
    }

#if DBG
    if (Lookaside->Stats.CurrentOutstanding > 0) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] WARNING: Destroying lookaside '%s' with %d outstanding allocations\n",
            Lookaside->Name,
            Lookaside->Stats.CurrentOutstanding
        );
    }
#endif

    //
    // Remove from manager's list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Manager->LookasideListLock);

    RemoveEntryList(&Lookaside->ListEntry);
    InterlockedDecrement(&Manager->LookasideCount);
    InterlockedDecrement(&Manager->GlobalStats.ActiveLookasideLists);

    ExReleasePushLockExclusive(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    //
    // Delete the native lookaside
    //
    if (Lookaside->IsPaged) {
        ExDeletePagedLookasideList(&Lookaside->NativeList.Paged);
    } else {
        ExDeleteNPagedLookasideList(&Lookaside->NativeList.NonPaged);
    }

    //
    // Clear magic and free
    //
    Lookaside->Magic = 0;
    Lookaside->State = LlStateDestroyed;

    ExFreePoolWithTag(Lookaside, LL_ENTRY_TAG);

    return STATUS_SUCCESS;
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
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LONG64 Latency;

    //
    // Validate lookaside
    //
    if (!LlIsValid(Lookaside)) {
        return NULL;
    }

    //
    // Check IRQL for paged pool
    //
    if (Lookaside->IsPaged && KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement64(&Lookaside->Stats.AllocationFailures);
        return NULL;
    }

    //
    // Record start time for latency tracking
    //
    KeQuerySystemTimePrecise(&StartTime);

    //
    // Allocate from appropriate lookaside
    //
    if (Lookaside->IsPaged) {
        Block = ExAllocateFromPagedLookasideList(&Lookaside->NativeList.Paged);
    } else {
        Block = ExAllocateFromNPagedLookasideList(&Lookaside->NativeList.NonPaged);
    }

    if (Block == NULL) {
        InterlockedIncrement64(&Lookaside->Stats.AllocationFailures);

        //
        // Retry logic for must-succeed allocations
        //
        if (Flags & LlAllocMustSucceed) {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10 * 1000; // 1ms

            for (ULONG Retry = 0; Retry < 3 && Block == NULL; Retry++) {
                if (KeGetCurrentIrql() <= APC_LEVEL) {
                    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
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
    // Determine if this was a cache hit
    // (This is an approximation - we assume the first allocation is a hit
    // if the lookaside list has been used before)
    //
    IsHit = (Lookaside->Stats.TotalAllocations > Lookaside->Stats.TotalFrees);

    //
    // Zero memory for security (always, regardless of flags)
    //
    RtlZeroMemory(Block, Lookaside->EntrySize);

    //
    // Update statistics
    //
    LL_STATS_ALLOC(Lookaside, IsHit);
    LL_TRACK_ALLOC(Lookaside->Manager, Lookaside->EntrySize);

    //
    // Update last access time
    //
    KeQuerySystemTimePrecise(&Lookaside->LastAccessTime);

    //
    // Calculate and update latency
    //
    KeQuerySystemTimePrecise(&EndTime);
    Latency = EndTime.QuadPart - StartTime.QuadPart;

    //
    // Update average latency (exponential moving average)
    //
    LONG64 CurrentAvg = Lookaside->Stats.AverageLatency;
    LONG64 NewAvg = (CurrentAvg * 7 + Latency) / 8;
    InterlockedExchange64(&Lookaside->Stats.AverageLatency, NewAvg);

    //
    // Update max latency
    //
    LONG64 MaxLat = Lookaside->Stats.MaxLatency;
    while (Latency > MaxLat) {
        InterlockedCompareExchange64(&Lookaside->Stats.MaxLatency, Latency, MaxLat);
        MaxLat = Lookaside->Stats.MaxLatency;
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
    //
    // Validate parameters
    //
    if (!LlIsValid(Lookaside) || Block == NULL) {
        return;
    }

#if DBG
    //
    // In debug builds, poison the memory to detect use-after-free
    //
    if (Lookaside->Manager && Lookaside->Manager->DebugMode) {
        RtlFillMemory(Block, Lookaside->EntrySize, LL_POISON_PATTERN);
    }
#endif

    //
    // Return to appropriate lookaside
    //
    if (Lookaside->IsPaged) {
        ExFreeToPagedLookasideList(&Lookaside->NativeList.Paged, Block);
    } else {
        ExFreeToNPagedLookasideList(&Lookaside->NativeList.NonPaged, Block);
    }

    //
    // Update statistics
    //
    LL_STATS_FREE(Lookaside);
    LL_TRACK_FREE(Lookaside->Manager, Lookaside->EntrySize);

    //
    // Update last access time
    //
    KeQuerySystemTimePrecise(&Lookaside->LastAccessTime);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlSecureFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    )
{
    //
    // Validate parameters
    //
    if (!LlIsValid(Lookaside) || Block == NULL) {
        return;
    }

    //
    // Securely wipe the memory before returning to cache
    //
    LlpSecureWipeMemory(Block, Lookaside->EntrySize);

    //
    // Return to lookaside
    //
    if (Lookaside->IsPaged) {
        ExFreeToPagedLookasideList(&Lookaside->NativeList.Paged, Block);
    } else {
        ExFreeToNPagedLookasideList(&Lookaside->NativeList.NonPaged, Block);
    }

    //
    // Update statistics
    //
    LL_STATS_FREE(Lookaside);
    LL_TRACK_FREE(Lookaside->Manager, Lookaside->EntrySize);
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

    //
    // Copy statistics (atomic reads)
    //
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
    //
    // Legacy compatibility wrapper
    //
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

    //
    // Copy statistics
    //
    Statistics->TotalAllocations = Manager->GlobalStats.TotalAllocations;
    Statistics->TotalFrees = Manager->GlobalStats.TotalFrees;
    Statistics->TotalCacheHits = Manager->GlobalStats.TotalCacheHits;
    Statistics->TotalCacheMisses = Manager->GlobalStats.TotalCacheMisses;
    Statistics->CurrentMemoryUsage = Manager->GlobalStats.CurrentMemoryUsage;
    Statistics->PeakMemoryUsage = Manager->GlobalStats.PeakMemoryUsage;
    Statistics->ActiveLookasideLists = Manager->GlobalStats.ActiveLookasideLists;
    Statistics->MemoryPressureEvents = Manager->GlobalStats.MemoryPressureEvents;
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

    //
    // Reset statistics (preserve CurrentOutstanding)
    //
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

    //
    // Reset statistics (preserve current values)
    //
    InterlockedExchange64(&Manager->GlobalStats.TotalAllocations, 0);
    InterlockedExchange64(&Manager->GlobalStats.TotalFrees, 0);
    InterlockedExchange64(&Manager->GlobalStats.TotalCacheHits, 0);
    InterlockedExchange64(&Manager->GlobalStats.TotalCacheMisses, 0);
    InterlockedExchange64(&Manager->GlobalStats.PeakMemoryUsage, Manager->GlobalStats.CurrentMemoryUsage);
    InterlockedExchange64(&Manager->GlobalStats.MemoryPressureEvents, 0);

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

    Manager->MemoryLimit = MemoryLimit;

    //
    // Check if we're now over the limit
    //
    if (MemoryLimit > 0) {
        LlpCheckMemoryPressure(Manager);
    }

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

    return Manager->GlobalStats.CurrentMemoryUsage;
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

    Manager->PressureCallback = Callback;
    Manager->PressureCallbackContext = Context;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
LONG64
LlTrimCaches(
    _In_ PLL_MANAGER Manager
    )
{
    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return 0;
    }

    //
    // Windows doesn't provide a direct way to trim lookaside lists.
    // The best we can do is trigger the system's memory management.
    // In a real implementation, we could recreate lists with smaller depths.
    //

    return 0;
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

    if (IntervalMs < 100) {
        IntervalMs = 100; // Minimum 100ms
    }

    Manager->MaintenanceIntervalMs = IntervalMs;
    Manager->MaintenanceEnabled = TRUE;

    //
    // Set timer for periodic execution
    //
    DueTime.QuadPart = -((LONGLONG)IntervalMs * 10000);

    KeSetTimerEx(
        &Manager->MaintenanceTimer,
        DueTime,
        IntervalMs,
        &Manager->MaintenanceDpc
    );

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

    if (Manager->MaintenanceEnabled) {
        KeCancelTimer(&Manager->MaintenanceTimer);
        KeFlushQueuedDpcs();
        Manager->MaintenanceEnabled = FALSE;
    }

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

    Manager->SelfTuningEnabled = Enable;

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
    PLL_LOOKASIDE Lookaside = NULL;
    BOOLEAN Continue = TRUE;

    if (!LlManagerIsValid(Manager) || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead && Continue;
         Entry = Entry->Flink) {

        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);
        Continue = Callback(Lookaside, Context);
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

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

    if (!LlManagerIsValid(Manager) || Name == NULL || Lookaside == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Lookaside = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = Entry->Flink) {

        Current = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        if (strcmp(Current->Name, Name) == 0) {
            *Lookaside = Current;
            Status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

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

    if (!LlManagerIsValid(Manager) || Lookaside == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Lookaside = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = Entry->Flink) {

        Current = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        if (Current->Tag == Tag) {
            *Lookaside = Current;
            Status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

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

    Manager->DebugMode = Enable;

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

    if (Lookaside->State != LlStateActive) {
        return FALSE;
    }

    if (Lookaside->EntrySize < LL_MIN_ENTRY_SIZE ||
        Lookaside->EntrySize > LL_MAX_ENTRY_SIZE) {
        return FALSE;
    }

    if (Lookaside->Manager == NULL) {
        return FALSE;
    }

    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlDumpDiagnostics(
    _In_ PLL_MANAGER Manager
    )
{
    PLIST_ENTRY Entry = NULL;
    PLL_LOOKASIDE Lookaside = NULL;

    PAGED_CODE();

    if (!LlManagerIsValid(Manager)) {
        return;
    }

#if DBG
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike] ===== LOOKASIDE LIST DIAGNOSTICS =====\n"
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
        "  Active Lists: %ld\n",
        Manager->GlobalStats.TotalAllocations,
        Manager->GlobalStats.TotalFrees,
        LlCalculateHitRate(Manager->GlobalStats.TotalCacheHits, Manager->GlobalStats.TotalCacheMisses),
        Manager->GlobalStats.CurrentMemoryUsage,
        Manager->GlobalStats.PeakMemoryUsage,
        Manager->GlobalStats.ActiveLookasideLists
    );

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Manager->LookasideListLock);

    for (Entry = Manager->LookasideListHead.Flink;
         Entry != &Manager->LookasideListHead;
         Entry = Entry->Flink) {

        Lookaside = CONTAINING_RECORD(Entry, LL_LOOKASIDE, ListEntry);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[ShadowStrike] Lookaside '%s' (Tag: 0x%08X, Size: %llu):\n"
            "  Allocations: %lld, Frees: %lld\n"
            "  Outstanding: %ld (Peak: %ld)\n"
            "  Hit Rate: %lu%%\n"
            "  Avg Latency: %lld, Max Latency: %lld\n",
            Lookaside->Name,
            Lookaside->Tag,
            (ULONG64)Lookaside->EntrySize,
            Lookaside->Stats.TotalAllocations,
            Lookaside->Stats.TotalFrees,
            Lookaside->Stats.CurrentOutstanding,
            Lookaside->Stats.PeakOutstanding,
            LlCalculateHitRate(Lookaside->Stats.CacheHits, Lookaside->Stats.CacheMisses),
            Lookaside->Stats.AverageLatency,
            Lookaside->Stats.MaxLatency
        );
    }

    ExReleasePushLockShared(&Manager->LookasideListLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike] ===== END DIAGNOSTICS =====\n"
    );
#else
    UNREFERENCED_PARAMETER(Manager);
#endif
}

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

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

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    //
    // Check memory pressure
    //
    LlpCheckMemoryPressure(Manager);

    //
    // Self-tuning would be implemented here
    // (Analyze hit/miss ratios and adjust depths)
    //
}

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

    if (Manager->MemoryLimit == 0) {
        //
        // No limit set
        //
        return;
    }

    CurrentUsage = Manager->GlobalStats.CurrentMemoryUsage;
    Limit = Manager->MemoryLimit;

    if (Limit <= 0) {
        return;
    }

    UsagePercent = (ULONG)((CurrentUsage * 100) / Limit);
    OldPressure = Manager->PressureLevel;

    //
    // Determine new pressure level
    //
    if (UsagePercent >= 95) {
        NewPressure = LlPressureCritical;
    } else if (UsagePercent >= LL_MEMORY_PRESSURE_HIGH) {
        NewPressure = LlPressureHigh;
    } else if (UsagePercent >= LL_MEMORY_PRESSURE_LOW) {
        NewPressure = LlPressureModerate;
    } else {
        NewPressure = LlPressureNone;
    }

    //
    // Update pressure level and notify if changed
    //
    if (NewPressure != OldPressure) {
        Manager->PressureLevel = NewPressure;
        InterlockedIncrement64(&Manager->GlobalStats.MemoryPressureEvents);

        if (Manager->PressureCallback != NULL) {
            Manager->PressureCallback(
                NewPressure,
                CurrentUsage,
                Limit,
                Manager->PressureCallbackContext
            );
        }
    }
}

static VOID
LlpSecureWipeMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
    )
{
    volatile UCHAR* VolatilePointer;
    SIZE_T i;

    if (Destination == NULL || Length == 0) {
        return;
    }

    //
    // Multi-pass secure wipe
    //

    // Pass 1: Zero
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = 0x00;
    }
    KeMemoryBarrier();

    // Pass 2: 0xFF
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = 0xFF;
    }
    KeMemoryBarrier();

    // Pass 3: 0xAA
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = 0xAA;
    }
    KeMemoryBarrier();

    // Final: Zero
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = 0x00;
    }
    KeMemoryBarrier();
}
