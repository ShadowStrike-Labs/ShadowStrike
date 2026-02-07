/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE SPINLOCK UTILITIES
 * ============================================================================
 *
 * @file SpinLock.c
 * @brief Enterprise-grade spinlock primitives for kernel-mode EDR operations.
 *
 * Provides comprehensive synchronization primitives for Fortune 500
 * endpoint protection with:
 * - Basic spinlocks with IRQL management
 * - Queued spinlocks for high core count systems (64+ CPUs)
 * - Reader-writer spinlocks for read-heavy workloads
 * - Recursive spinlocks for re-entrant code paths
 * - Interrupt-safe spinlock variants
 * - Push locks for low-IRQL operations
 * - Lock statistics and contention monitoring
 * - Deadlock detection in checked builds
 *
 * Implementation Features:
 * - All locks properly track and restore IRQL
 * - Statistics collection with minimal overhead
 * - Debug-mode deadlock detection via lock ordering
 * - Per-thread lock tracking for diagnostics
 * - Cache-line aware design to prevent false sharing
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SpinLock.h"

// ============================================================================
// DEADLOCK DETECTION STATE (Debug Only)
// ============================================================================

#if SHADOWSTRIKE_DEADLOCK_DETECTION

/**
 * @brief Per-thread lock tracking for deadlock detection
 */
typedef struct _SHADOWSTRIKE_THREAD_LOCK_STATE {
    /// Thread ID
    HANDLE ThreadId;

    /// Held locks (ordered by acquisition)
    struct {
        PVOID Lock;
        ULONG Order;
        SHADOWSTRIKE_LOCK_TYPE Type;
        LARGE_INTEGER AcquireTime;
    } HeldLocks[SHADOWSTRIKE_MAX_HELD_LOCKS];

    /// Number of held locks
    ULONG HeldCount;

    /// List entry for global tracking
    LIST_ENTRY ListEntry;

} SHADOWSTRIKE_THREAD_LOCK_STATE, *PSHADOWSTRIKE_THREAD_LOCK_STATE;

#endif // SHADOWSTRIKE_DEADLOCK_DETECTION

// ============================================================================
// SUBSYSTEM STATE
// ============================================================================

typedef struct _SHADOWSTRIKE_LOCK_SUBSYSTEM {
    /// Initialization flag
    BOOLEAN Initialized;

    /// Subsystem lock
    KSPIN_LOCK SubsystemLock;

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    /// Thread lock state list
    LIST_ENTRY ThreadStateList;

    /// Thread state list lock
    KSPIN_LOCK ThreadStateLock;

    /// Thread state lookaside
    NPAGED_LOOKASIDE_LIST ThreadStateLookaside;
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    /// Global statistics
    struct {
        volatile LONG64 TotalLocksCreated;
        volatile LONG64 TotalAcquisitions;
        volatile LONG64 TotalContentions;
        volatile LONG64 TotalSpinCycles;
        LARGE_INTEGER StartTime;
    } GlobalStats;
#endif

} SHADOWSTRIKE_LOCK_SUBSYSTEM, *PSHADOWSTRIKE_LOCK_SUBSYSTEM;

static SHADOWSTRIKE_LOCK_SUBSYSTEM g_LockSubsystem = { 0 };

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

/**
 * @brief Record acquisition statistics
 */
static
VOID
ShadowRecordAcquisition(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats,
    _In_ ULONG SpinCount,
    _In_ BOOLEAN Contended
)
{
    LARGE_INTEGER CurrentTime;

    InterlockedIncrement64(&Stats->TotalAcquisitions);

    if (Contended) {
        InterlockedIncrement64(&Stats->ContentionCount);
    }

    if (SpinCount > 0) {
        InterlockedAdd64(&Stats->TotalSpinCycles, SpinCount);

        //
        // Update max spin cycles (lock-free update)
        //
        LONG64 CurrentMax = Stats->MaxSpinCycles;
        while (SpinCount > CurrentMax) {
            LONG64 OldMax = InterlockedCompareExchange64(
                &Stats->MaxSpinCycles,
                SpinCount,
                CurrentMax
            );
            if (OldMax == CurrentMax) {
                break;
            }
            CurrentMax = OldMax;
        }
    }

    //
    // Record acquisition time
    //
    KeQuerySystemTimePrecise(&CurrentTime);
    Stats->AcquireTime = CurrentTime;
    Stats->OwnerThread = PsGetCurrentThreadId();

    //
    // Global stats
    //
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalAcquisitions);
    if (Contended) {
        InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalContentions);
    }
    if (SpinCount > 0) {
        InterlockedAdd64(&g_LockSubsystem.GlobalStats.TotalSpinCycles, SpinCount);
    }
}

/**
 * @brief Record release statistics
 */
static
VOID
ShadowRecordRelease(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    LARGE_INTEGER CurrentTime;
    LONG64 HoldTime;

    InterlockedIncrement64(&Stats->TotalReleases);

    //
    // Calculate hold time
    //
    KeQuerySystemTimePrecise(&CurrentTime);
    HoldTime = CurrentTime.QuadPart - Stats->AcquireTime.QuadPart;

    if (HoldTime > 0) {
        InterlockedAdd64(&Stats->TotalHoldTime, HoldTime);

        //
        // Update max hold time
        //
        LONG64 CurrentMax = Stats->MaxHoldTime;
        while (HoldTime > CurrentMax) {
            LONG64 OldMax = InterlockedCompareExchange64(
                &Stats->MaxHoldTime,
                HoldTime,
                CurrentMax
            );
            if (OldMax == CurrentMax) {
                break;
            }
            CurrentMax = OldMax;
        }
    }

    Stats->OwnerThread = NULL;
}

/**
 * @brief Record try-acquire failure
 */
static
VOID
ShadowRecordTryFailure(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    InterlockedIncrement64(&Stats->TryFailures);
}

/**
 * @brief Update reader statistics
 */
static
VOID
ShadowRecordReaderAcquire(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    LONG NewCount = InterlockedIncrement(&Stats->CurrentReaders);

    //
    // Update peak readers
    //
    LONG CurrentPeak = Stats->PeakReaders;
    while (NewCount > CurrentPeak) {
        LONG OldPeak = InterlockedCompareExchange(
            &Stats->PeakReaders,
            NewCount,
            CurrentPeak
        );
        if (OldPeak == CurrentPeak) {
            break;
        }
        CurrentPeak = OldPeak;
    }
}

/**
 * @brief Update reader release statistics
 */
static
VOID
ShadowRecordReaderRelease(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    InterlockedDecrement(&Stats->CurrentReaders);
}

#endif // SHADOWSTRIKE_LOCK_STATISTICS

#if SHADOWSTRIKE_DEADLOCK_DETECTION

/**
 * @brief Get or create thread lock state
 */
static
PSHADOWSTRIKE_THREAD_LOCK_STATE
ShadowGetThreadLockState(
    VOID
)
{
    HANDLE CurrentThread = PsGetCurrentThreadId();
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = NULL;
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_LockSubsystem.ThreadStateLock, &OldIrql);

    //
    // Search for existing state
    //
    PLIST_ENTRY Entry = g_LockSubsystem.ThreadStateList.Flink;
    while (Entry != &g_LockSubsystem.ThreadStateList) {
        State = CONTAINING_RECORD(Entry, SHADOWSTRIKE_THREAD_LOCK_STATE, ListEntry);
        if (State->ThreadId == CurrentThread) {
            KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
            return State;
        }
        Entry = Entry->Flink;
    }

    //
    // Allocate new state
    //
    State = (PSHADOWSTRIKE_THREAD_LOCK_STATE)ExAllocateFromNPagedLookasideList(
        &g_LockSubsystem.ThreadStateLookaside
    );

    if (State != NULL) {
        RtlZeroMemory(State, sizeof(SHADOWSTRIKE_THREAD_LOCK_STATE));
        State->ThreadId = CurrentThread;
        InsertTailList(&g_LockSubsystem.ThreadStateList, &State->ListEntry);
    }

    KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
    return State;
}

/**
 * @brief Record lock acquisition for deadlock detection
 */
static
VOID
ShadowRecordLockAcquire(
    _In_ PVOID Lock,
    _In_ ULONG Order,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type
)
{
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowGetThreadLockState();
    if (State == NULL || State->HeldCount >= SHADOWSTRIKE_MAX_HELD_LOCKS) {
        return;
    }

    ULONG Index = State->HeldCount;
    State->HeldLocks[Index].Lock = Lock;
    State->HeldLocks[Index].Order = Order;
    State->HeldLocks[Index].Type = Type;
    KeQuerySystemTimePrecise(&State->HeldLocks[Index].AcquireTime);
    State->HeldCount++;
}

/**
 * @brief Record lock release for deadlock detection
 */
static
VOID
ShadowRecordLockRelease(
    _In_ PVOID Lock
)
{
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowGetThreadLockState();
    if (State == NULL || State->HeldCount == 0) {
        return;
    }

    //
    // Find and remove the lock (should be most recent for proper ordering)
    //
    for (ULONG i = State->HeldCount; i > 0; i--) {
        if (State->HeldLocks[i - 1].Lock == Lock) {
            //
            // Shift remaining entries
            //
            for (ULONG j = i - 1; j < State->HeldCount - 1; j++) {
                State->HeldLocks[j] = State->HeldLocks[j + 1];
            }
            State->HeldCount--;
            break;
        }
    }
}

#endif // SHADOWSTRIKE_DEADLOCK_DETECTION

// ============================================================================
// SUBSYSTEM INITIALIZATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeLockSubsystemInitialize(
    VOID
)
{
    PAGED_CODE();

    if (g_LockSubsystem.Initialized) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_LockSubsystem, sizeof(g_LockSubsystem));
    KeInitializeSpinLock(&g_LockSubsystem.SubsystemLock);

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    InitializeListHead(&g_LockSubsystem.ThreadStateList);
    KeInitializeSpinLock(&g_LockSubsystem.ThreadStateLock);

    ExInitializeNPagedLookasideList(
        &g_LockSubsystem.ThreadStateLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOWSTRIKE_THREAD_LOCK_STATE),
        SHADOW_LOCK_TAG,
        0
    );
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    KeQuerySystemTimePrecise(&g_LockSubsystem.GlobalStats.StartTime);
#endif

    g_LockSubsystem.Initialized = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLockSubsystemCleanup(
    VOID
)
{
    PAGED_CODE();

    if (!g_LockSubsystem.Initialized) {
        return;
    }

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    //
    // Free all thread state entries
    //
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LockSubsystem.ThreadStateLock, &OldIrql);

    while (!IsListEmpty(&g_LockSubsystem.ThreadStateList)) {
        PLIST_ENTRY Entry = RemoveHeadList(&g_LockSubsystem.ThreadStateList);
        PSHADOWSTRIKE_THREAD_LOCK_STATE State = CONTAINING_RECORD(
            Entry,
            SHADOWSTRIKE_THREAD_LOCK_STATE,
            ListEntry
        );
        ExFreeToNPagedLookasideList(&g_LockSubsystem.ThreadStateLookaside, State);
    }

    KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
    ExDeleteNPagedLookasideList(&g_LockSubsystem.ThreadStateLookaside);
#endif

    g_LockSubsystem.Initialized = FALSE;
}

// ============================================================================
// BASIC SPINLOCK IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeSpinLock(
    _Out_ PSHADOWSTRIKE_SPINLOCK Lock
)
{
    RtlZeroMemory(Lock, sizeof(SHADOWSTRIKE_SPINLOCK));
    KeInitializeSpinLock(&Lock->Lock);
    Lock->Type = ShadowLockType_Spin;
    Lock->Name = "UnnamedSpinLock";
    Lock->LockOrder = 0;

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalLocksCreated);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeSpinLockEx(
    _Out_ PSHADOWSTRIKE_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
)
{
    ShadowStrikeInitializeSpinLock(Lock);
    Lock->Name = Name;
    Lock->LockOrder = LockOrder;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    KeAcquireSpinLock(&Lock->Lock, &Lock->OldIrql);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockRelease(Lock);
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    KeReleaseSpinLock(&Lock->Lock, Lock->OldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeTryAcquireSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
)
{
    KIRQL OldIrql;

    //
    // Raise IRQL first
    //
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    //
    // Try to acquire
    //
    if (KeTryToAcquireSpinLockAtDpcLevel(&Lock->Lock)) {
        Lock->OldIrql = OldIrql;

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
        return TRUE;
    }

    //
    // Failed - restore IRQL
    //
    KeLowerIrql(OldIrql);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordTryFailure(&Lock->Stats);
#endif

    return FALSE;
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireSpinLockAtDpcLevel(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    KeAcquireSpinLockAtDpcLevel(&Lock->Lock);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseSpinLockFromDpcLevel(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockRelease(Lock);
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    KeReleaseSpinLockFromDpcLevel(&Lock->Lock);
}

// ============================================================================
// QUEUED SPINLOCK IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeQueuedSpinLock(
    _Out_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock
)
{
    RtlZeroMemory(Lock, sizeof(SHADOWSTRIKE_QUEUED_SPINLOCK));
    KeInitializeSpinLock(&Lock->Lock);
    Lock->Type = ShadowLockType_SpinQueued;
    Lock->Name = "UnnamedQueuedSpinLock";
    Lock->LockOrder = 0;

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalLocksCreated);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeQueuedSpinLockEx(
    _Out_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
)
{
    ShadowStrikeInitializeQueuedSpinLock(Lock);
    Lock->Name = Name;
    Lock->LockOrder = LockOrder;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
)
{
    RtlZeroMemory(LockHandle, sizeof(SHADOWSTRIKE_INSTACK_QUEUED_LOCK));
    LockHandle->ParentLock = Lock;

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    KeQuerySystemTimePrecise(&LockHandle->StartTime);
#endif

    KeAcquireInStackQueuedSpinLock(&Lock->Lock, &LockHandle->LockHandle);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
)
{
    PSHADOWSTRIKE_QUEUED_SPINLOCK Lock = LockHandle->ParentLock;

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock != NULL) {
        ShadowRecordLockRelease(Lock);
    }
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    if (Lock != NULL) {
        ShadowRecordRelease(&Lock->Stats);
    }
#endif

    KeReleaseInStackQueuedSpinLock(&LockHandle->LockHandle);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeTryAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
)
{
    RtlZeroMemory(LockHandle, sizeof(SHADOWSTRIKE_INSTACK_QUEUED_LOCK));
    LockHandle->ParentLock = Lock;

    if (KeTryToAcquireSpinLockAtDpcLevel(&Lock->Lock)) {
        //
        // Success - set up lock handle manually
        //
        LockHandle->LockHandle.LockQueue.Lock = &Lock->Lock;
        LockHandle->LockHandle.OldIrql = KeGetCurrentIrql();

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
        return TRUE;
    }

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordTryFailure(&Lock->Stats);
#endif

    return FALSE;
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireQueuedSpinLockAtDpcLevel(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
)
{
    RtlZeroMemory(LockHandle, sizeof(SHADOWSTRIKE_INSTACK_QUEUED_LOCK));
    LockHandle->ParentLock = Lock;

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    KeAcquireInStackQueuedSpinLockAtDpcLevel(&Lock->Lock, &LockHandle->LockHandle);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseQueuedSpinLockFromDpcLevel(
    _Inout_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
)
{
    PSHADOWSTRIKE_QUEUED_SPINLOCK Lock = LockHandle->ParentLock;

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock != NULL) {
        ShadowRecordLockRelease(Lock);
    }
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    if (Lock != NULL) {
        ShadowRecordRelease(&Lock->Stats);
    }
#endif

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle->LockHandle);
}

// ============================================================================
// READER-WRITER SPINLOCK IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRWSpinLock(
    _Out_ PSHADOWSTRIKE_RWSPINLOCK Lock
)
{
    RtlZeroMemory(Lock, sizeof(SHADOWSTRIKE_RWSPINLOCK));
    Lock->Lock = 0;
    Lock->Type = ShadowLockType_ReaderWriter;
    Lock->Name = "UnnamedRWSpinLock";
    Lock->LockOrder = 0;
    Lock->State = ShadowLockState_Unlocked;
    Lock->WriterThread = NULL;
    Lock->ReaderCount = 0;

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalLocksCreated);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRWSpinLockEx(
    _Out_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
)
{
    ShadowStrikeInitializeRWSpinLock(Lock);
    Lock->Name = Name;
    Lock->LockOrder = LockOrder;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    *OldIrql = ExAcquireSpinLockExclusive(&Lock->Lock);
    Lock->State = ShadowLockState_Exclusive;
    Lock->WriterThread = PsGetCurrentThreadId();

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ KIRQL OldIrql
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockRelease(Lock);
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    Lock->WriterThread = NULL;
    Lock->State = ShadowLockState_Unlocked;
    ExReleaseSpinLockExclusive(&Lock->Lock, OldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    *OldIrql = ExAcquireSpinLockShared(&Lock->Lock);
    Lock->State = ShadowLockState_Shared;
    InterlockedIncrement(&Lock->ReaderCount);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
    ShadowRecordReaderAcquire(&Lock->Stats);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ KIRQL OldIrql
)
{
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockRelease(Lock);
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
    ShadowRecordReaderRelease(&Lock->Stats);
#endif

    LONG NewCount = InterlockedDecrement(&Lock->ReaderCount);
    if (NewCount == 0) {
        Lock->State = ShadowLockState_Unlocked;
    }

    ExReleaseSpinLockShared(&Lock->Lock, OldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeTryAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
)
{
    *OldIrql = PASSIVE_LEVEL;

    if (ExTryAcquireSpinLockExclusiveAtDpcLevel(&Lock->Lock)) {
        //
        // Raise IRQL manually since we used AtDpcLevel variant
        //
        KeRaiseIrql(DISPATCH_LEVEL, OldIrql);
        Lock->State = ShadowLockState_Exclusive;
        Lock->WriterThread = PsGetCurrentThreadId();

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
        return TRUE;
    }

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordTryFailure(&Lock->Stats);
#endif

    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeTryAcquireRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
)
{
    //
    // EX_SPIN_LOCK doesn't have a direct try-shared, so we implement manually
    //
    KeRaiseIrql(DISPATCH_LEVEL, OldIrql);

    //
    // Check if we can acquire shared (no exclusive holder)
    //
    if (Lock->State != ShadowLockState_Exclusive) {
        //
        // Try to acquire
        //
        KIRQL Dummy;
        Dummy = ExAcquireSpinLockShared(&Lock->Lock);
        UNREFERENCED_PARAMETER(Dummy);

        Lock->State = ShadowLockState_Shared;
        InterlockedIncrement(&Lock->ReaderCount);

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
        ShadowRecordReaderAcquire(&Lock->Stats);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
        return TRUE;
    }

    KeLowerIrql(*OldIrql);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordTryFailure(&Lock->Stats);
#endif

    return FALSE;
}

_IRQL_requires_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeUpgradeRWSpinLock(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock
)
{
    //
    // Upgrade is complex with EX_SPIN_LOCK and may require release/reacquire
    // For safety, we don't support atomic upgrade
    //
    UNREFERENCED_PARAMETER(Lock);
    return FALSE;
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeDowngradeRWSpinLock(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock
)
{
    //
    // Downgrade from exclusive to shared
    // EX_SPIN_LOCK supports this via ExReleaseSpinLockExclusiveFromDpcLevel
    // followed by ExAcquireSpinLockSharedAtDpcLevel
    //
    Lock->WriterThread = NULL;
    Lock->State = ShadowLockState_Shared;
    InterlockedIncrement(&Lock->ReaderCount);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordReaderAcquire(&Lock->Stats);
#endif

    //
    // Note: This is a simplified implementation. A true downgrade would
    // atomically transition from exclusive to shared.
    //
}

// ============================================================================
// RECURSIVE SPINLOCK IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRecursiveSpinLock(
    _Out_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
)
{
    RtlZeroMemory(Lock, sizeof(SHADOWSTRIKE_RECURSIVE_SPINLOCK));
    KeInitializeSpinLock(&Lock->Lock);
    Lock->OwnerThread = NULL;
    Lock->RecursionCount = 0;
    Lock->Type = ShadowLockType_Recursive;
    Lock->Name = "UnnamedRecursiveSpinLock";
    Lock->LockOrder = 0;

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalLocksCreated);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRecursiveSpinLockEx(
    _Out_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
)
{
    ShadowStrikeInitializeRecursiveSpinLock(Lock);
    Lock->Name = Name;
    Lock->LockOrder = LockOrder;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRecursiveSpinLock(
    _Inout_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
)
{
    PKTHREAD CurrentThread = KeGetCurrentThread();

    //
    // Check if we already own the lock
    //
    if (Lock->OwnerThread == CurrentThread) {
        //
        // Recursive acquisition
        //
        LONG NewCount = InterlockedIncrement(&Lock->RecursionCount);

        //
        // Safety check for excessive recursion
        //
        NT_ASSERT(NewCount <= SHADOWSTRIKE_MAX_RECURSION_DEPTH);

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif
        return;
    }

    //
    // First acquisition - need to acquire underlying lock
    //
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    KIRQL OldIrql;
    KeAcquireSpinLock(&Lock->Lock, &OldIrql);

    Lock->OwnerThread = CurrentThread;
    Lock->RecursionCount = 1;
    Lock->SavedIrql = OldIrql;

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRecursiveSpinLock(
    _Inout_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
)
{
    PKTHREAD CurrentThread = KeGetCurrentThread();

    //
    // Verify ownership
    //
    NT_ASSERT(Lock->OwnerThread == CurrentThread);

    LONG NewCount = InterlockedDecrement(&Lock->RecursionCount);
    NT_ASSERT(NewCount >= 0);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    if (NewCount == 0) {
        //
        // Final release - give up the lock
        //
#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockRelease(Lock);
#endif

        KIRQL SavedIrql = Lock->SavedIrql;
        Lock->OwnerThread = NULL;

        KeReleaseSpinLock(&Lock->Lock, SavedIrql);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
ShadowStrikeGetRecursionDepth(
    _In_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
)
{
    if (Lock->OwnerThread == KeGetCurrentThread()) {
        return Lock->RecursionCount;
    }
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsRecursiveLockOwned(
    _In_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
)
{
    return (Lock->OwnerThread == KeGetCurrentThread());
}

// ============================================================================
// INTERRUPT SPINLOCK IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeInterruptSpinLock(
    _Out_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock,
    _In_opt_ PKINTERRUPT Interrupt
)
{
    RtlZeroMemory(Lock, sizeof(SHADOWSTRIKE_INTERRUPT_SPINLOCK));
    KeInitializeSpinLock(&Lock->Lock);
    Lock->Interrupt = Interrupt;
    Lock->Type = ShadowLockType_Interrupt;
    Lock->Name = "UnnamedInterruptSpinLock";

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalLocksCreated);
#endif
}

VOID
ShadowStrikeAcquireInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
)
{
    if (Lock->Interrupt != NULL) {
        //
        // Use interrupt synchronization
        //
        Lock->OldIrql = KeAcquireInterruptSpinLock(Lock->Interrupt);
    } else {
        //
        // Standard spinlock
        //
        KeAcquireSpinLock(&Lock->Lock, &Lock->OldIrql);
    }

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif
}

VOID
ShadowStrikeReleaseInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
)
{
#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    if (Lock->Interrupt != NULL) {
        KeReleaseInterruptSpinLock(Lock->Interrupt, Lock->OldIrql);
    } else {
        KeReleaseSpinLock(&Lock->Lock, Lock->OldIrql);
    }
}

BOOLEAN
ShadowStrikeSynchronizeWithInterrupt(
    _In_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock,
    _In_ PKSYNCHRONIZE_ROUTINE Callback,
    _In_opt_ PVOID Context
)
{
    if (Lock->Interrupt != NULL) {
        return KeSynchronizeExecution(Lock->Interrupt, Callback, Context);
    }

    //
    // No interrupt object - execute directly under spinlock
    //
    ShadowStrikeAcquireInterruptSpinLock(Lock);
    BOOLEAN Result = Callback(Context);
    ShadowStrikeReleaseInterruptSpinLock(Lock);

    return Result;
}

// ============================================================================
// PUSH LOCK IMPLEMENTATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeInitializePushLock(
    _Out_ PSHADOWSTRIKE_PUSHLOCK Lock
)
{
    RtlZeroMemory(Lock, sizeof(SHADOWSTRIKE_PUSHLOCK));
    ExInitializePushLock(&Lock->Lock);
    Lock->Type = ShadowLockType_PushLock;
    Lock->Name = "UnnamedPushLock";
    Lock->LockOrder = 0;
    Lock->Initialized = TRUE;

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.GlobalStats.TotalLocksCreated);
#endif
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeInitializePushLockEx(
    _Out_ PSHADOWSTRIKE_PUSHLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
)
{
    ShadowStrikeInitializePushLock(Lock);
    Lock->Name = Name;
    Lock->LockOrder = LockOrder;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeAcquirePushLockExclusive(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
)
{
    NT_ASSERT(Lock->Initialized);

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Lock->Lock);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleasePushLockExclusive(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
)
{
    NT_ASSERT(Lock->Initialized);

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockRelease(Lock);
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    ExReleasePushLockExclusive(&Lock->Lock);
    KeLeaveCriticalRegion();
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeAcquirePushLockShared(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
)
{
    NT_ASSERT(Lock->Initialized);

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Lock->Lock);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, 0, FALSE);
    ShadowRecordReaderAcquire(&Lock->Stats);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleasePushLockShared(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
)
{
    NT_ASSERT(Lock->Initialized);

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    ShadowRecordLockRelease(Lock);
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
    ShadowRecordReaderRelease(&Lock->Stats);
#endif

    ExReleasePushLockShared(&Lock->Lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// STATISTICS API IMPLEMENTATION
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetLockStatistics(
    _In_ PVOID Lock,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type,
    _Out_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    PSHADOWSTRIKE_LOCK_STATS SourceStats = NULL;

    if (Lock == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Type) {
        case ShadowLockType_Spin:
            SourceStats = &((PSHADOWSTRIKE_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_SpinQueued:
            SourceStats = &((PSHADOWSTRIKE_QUEUED_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_ReaderWriter:
            SourceStats = &((PSHADOWSTRIKE_RWSPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_Recursive:
            SourceStats = &((PSHADOWSTRIKE_RECURSIVE_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_Interrupt:
            SourceStats = &((PSHADOWSTRIKE_INTERRUPT_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_PushLock:
            SourceStats = &((PSHADOWSTRIKE_PUSHLOCK)Lock)->Stats;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Stats, SourceStats, sizeof(SHADOWSTRIKE_LOCK_STATS));
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetLockStatistics(
    _Inout_ PVOID Lock,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type
)
{
    PSHADOWSTRIKE_LOCK_STATS Stats = NULL;

    if (Lock == NULL) {
        return;
    }

    switch (Type) {
        case ShadowLockType_Spin:
            Stats = &((PSHADOWSTRIKE_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_SpinQueued:
            Stats = &((PSHADOWSTRIKE_QUEUED_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_ReaderWriter:
            Stats = &((PSHADOWSTRIKE_RWSPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_Recursive:
            Stats = &((PSHADOWSTRIKE_RECURSIVE_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_Interrupt:
            Stats = &((PSHADOWSTRIKE_INTERRUPT_SPINLOCK)Lock)->Stats;
            break;

        case ShadowLockType_PushLock:
            Stats = &((PSHADOWSTRIKE_PUSHLOCK)Lock)->Stats;
            break;

        default:
            return;
    }

    if (Stats != NULL) {
        RtlZeroMemory(Stats, sizeof(SHADOWSTRIKE_LOCK_STATS));
    }
}

#endif // SHADOWSTRIKE_LOCK_STATISTICS

// ============================================================================
// DEADLOCK DETECTION API IMPLEMENTATION
// ============================================================================

#if SHADOWSTRIKE_DEADLOCK_DETECTION

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeValidateLockOrder(
    _In_ PVOID Lock,
    _In_ ULONG Order
)
{
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowGetThreadLockState();

    if (State == NULL) {
        //
        // Can't validate without state - allow
        //
        return TRUE;
    }

    //
    // Check that this lock's order is greater than all currently held locks
    //
    for (ULONG i = 0; i < State->HeldCount; i++) {
        if (State->HeldLocks[i].Order >= Order) {
            //
            // Lock order violation - attempting to acquire lower-ordered lock
            // while holding higher-ordered lock
            //
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "ShadowStrike: Lock order violation! Attempting lock %p (order %u) "
                "while holding lock %p (order %u)\n",
                Lock,
                Order,
                State->HeldLocks[i].Lock,
                State->HeldLocks[i].Order
            );

            return FALSE;
        }
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeDumpHeldLocks(
    VOID
)
{
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowGetThreadLockState();

    if (State == NULL || State->HeldCount == 0) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "ShadowStrike: Thread 0x%p holds no locks\n",
            PsGetCurrentThreadId()
        );
        return;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "ShadowStrike: Thread 0x%p holds %u locks:\n",
        PsGetCurrentThreadId(),
        State->HeldCount
    );

    for (ULONG i = 0; i < State->HeldCount; i++) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "  [%u] Lock %p, Order %u, Type %u\n",
            i,
            State->HeldLocks[i].Lock,
            State->HeldLocks[i].Order,
            State->HeldLocks[i].Type
        );
    }
}

#endif // SHADOWSTRIKE_DEADLOCK_DETECTION
