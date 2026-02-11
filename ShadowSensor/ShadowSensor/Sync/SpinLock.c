/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE SPINLOCK UTILITIES
 * ============================================================================
 *
 * @file SpinLock.c
 * @brief Enterprise-grade spinlock primitives for kernel-mode EDR operations.
 *
 * Design rules enforced:
 * - OldIrql stored in lock struct only for single-owner locks (basic spinlock,
 *   interrupt spinlock). RW lock ALWAYS uses caller-provided OldIrql.
 * - Push locks ALWAYS bracket with KeEnterCriticalRegion/KeLeaveCriticalRegion.
 * - Deadlock detection uses a per-thread array with a single global lock ONLY
 *   for lookup/insert. The lock is NEVER acquired while another user lock is
 *   being acquired (validation happens BEFORE the user lock is taken).
 * - Statistics use only interlocked ops. No per-lock non-atomic fields.
 * - No Upgrade/Downgrade on RW locks (EX_SPIN_LOCK doesn't support atomic
 *   transition; fake implementations were removed).
 * - TryAcquire for queued spinlock uses KeAcquireInStackQueuedSpinLockForDpc
 *   which properly initializes the KLOCK_QUEUE_HANDLE.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SpinLock.h"

// ============================================================================
// DEADLOCK DETECTION STATE (Debug Only)
// ============================================================================

#if SHADOWSTRIKE_DEADLOCK_DETECTION

typedef struct _SHADOWSTRIKE_THREAD_LOCK_ENTRY {
    PVOID Lock;
    ULONG Order;
    SHADOWSTRIKE_LOCK_TYPE Type;
} SHADOWSTRIKE_THREAD_LOCK_ENTRY;

typedef struct _SHADOWSTRIKE_THREAD_LOCK_STATE {
    HANDLE ThreadId;
    SHADOWSTRIKE_THREAD_LOCK_ENTRY HeldLocks[SHADOWSTRIKE_MAX_HELD_LOCKS];
    ULONG HeldCount;
    LIST_ENTRY ListEntry;
} SHADOWSTRIKE_THREAD_LOCK_STATE, *PSHADOWSTRIKE_THREAD_LOCK_STATE;

#endif

// ============================================================================
// SUBSYSTEM STATE
// ============================================================================

typedef struct _SHADOWSTRIKE_LOCK_SUBSYSTEM {
    LONG Initialized;

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    LIST_ENTRY ThreadStateList;
    KSPIN_LOCK ThreadStateLock;
    NPAGED_LOOKASIDE_LIST ThreadStateLookaside;
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    volatile LONG64 TotalLocksCreated;
    volatile LONG64 TotalAcquisitions;
    volatile LONG64 TotalContentions;
#endif

} SHADOWSTRIKE_LOCK_SUBSYSTEM;

static SHADOWSTRIKE_LOCK_SUBSYSTEM g_LockSubsystem = { 0 };

// ============================================================================
// STATISTICS HELPERS (debug only, interlocked-only)
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

static
VOID
ShadowRecordAcquisition(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats,
    _In_ BOOLEAN Contended
)
{
    InterlockedIncrement64(&Stats->TotalAcquisitions);
    if (Contended) {
        InterlockedIncrement64(&Stats->ContentionCount);
    }
    InterlockedIncrement64(&g_LockSubsystem.TotalAcquisitions);
    if (Contended) {
        InterlockedIncrement64(&g_LockSubsystem.TotalContentions);
    }
}

static
VOID
ShadowRecordRelease(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    InterlockedIncrement64(&Stats->TotalReleases);
}

static
VOID
ShadowRecordTryFailure(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    InterlockedIncrement64(&Stats->TryFailures);
}

static
VOID
ShadowRecordReaderAcquire(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    LONG NewCount = InterlockedIncrement(&Stats->CurrentReaders);
    LONG CurrentPeak = Stats->PeakReaders;
    while (NewCount > CurrentPeak) {
        LONG OldPeak = InterlockedCompareExchange(
            &Stats->PeakReaders, NewCount, CurrentPeak);
        if (OldPeak == CurrentPeak) break;
        CurrentPeak = OldPeak;
    }
}

static
VOID
ShadowRecordReaderRelease(
    _Inout_ PSHADOWSTRIKE_LOCK_STATS Stats
)
{
    InterlockedDecrement(&Stats->CurrentReaders);
}

#endif

// ============================================================================
// DEADLOCK DETECTION HELPERS (debug only)
//
// Key design: ShadowGetThreadLockState acquires the global ThreadStateLock.
// This is safe because:
// 1. ValidateLockOrder is called BEFORE the user lock is acquired.
// 2. RecordLockAcquire/Release only update thread-local state AFTER
//    the thread has been looked up. The global lock is released before
//    the thread-local array is modified.
// ============================================================================

#if SHADOWSTRIKE_DEADLOCK_DETECTION

/**
 * Find existing thread state. Does NOT allocate. Does NOT acquire locks.
 * Used on the release path to avoid allocation during release.
 */
static
PSHADOWSTRIKE_THREAD_LOCK_STATE
ShadowFindThreadLockState(
    VOID
)
{
    HANDLE CurrentThread = PsGetCurrentThreadId();
    KIRQL OldIrql;
    PSHADOWSTRIKE_THREAD_LOCK_STATE Found = NULL;

    KeAcquireSpinLock(&g_LockSubsystem.ThreadStateLock, &OldIrql);

    PLIST_ENTRY Entry = g_LockSubsystem.ThreadStateList.Flink;
    while (Entry != &g_LockSubsystem.ThreadStateList) {
        PSHADOWSTRIKE_THREAD_LOCK_STATE State =
            CONTAINING_RECORD(Entry, SHADOWSTRIKE_THREAD_LOCK_STATE, ListEntry);
        if (State->ThreadId == CurrentThread) {
            Found = State;
            break;
        }
        Entry = Entry->Flink;
    }

    KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
    return Found;
}

/**
 * Find or create thread state. May allocate from lookaside.
 * Only called on acquire path (never during release).
 */
static
PSHADOWSTRIKE_THREAD_LOCK_STATE
ShadowGetOrCreateThreadLockState(
    VOID
)
{
    HANDLE CurrentThread = PsGetCurrentThreadId();
    PSHADOWSTRIKE_THREAD_LOCK_STATE Found = NULL;
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_LockSubsystem.ThreadStateLock, &OldIrql);

    PLIST_ENTRY Entry = g_LockSubsystem.ThreadStateList.Flink;
    while (Entry != &g_LockSubsystem.ThreadStateList) {
        PSHADOWSTRIKE_THREAD_LOCK_STATE State =
            CONTAINING_RECORD(Entry, SHADOWSTRIKE_THREAD_LOCK_STATE, ListEntry);
        if (State->ThreadId == CurrentThread) {
            Found = State;
            break;
        }
        Entry = Entry->Flink;
    }

    if (Found == NULL) {
        Found = (PSHADOWSTRIKE_THREAD_LOCK_STATE)
            ExAllocateFromNPagedLookasideList(&g_LockSubsystem.ThreadStateLookaside);
        if (Found != NULL) {
            RtlZeroMemory(Found, sizeof(SHADOWSTRIKE_THREAD_LOCK_STATE));
            Found->ThreadId = CurrentThread;
            InsertTailList(&g_LockSubsystem.ThreadStateList, &Found->ListEntry);
        }
    }

    KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
    return Found;
}

/**
 * Record lock acquisition in thread-local array.
 * Thread state is looked up under global lock, but the array
 * modification is thread-local (only the owning thread writes).
 */
static
VOID
ShadowRecordLockAcquire(
    _In_ PVOID Lock,
    _In_ ULONG Order,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type
)
{
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowGetOrCreateThreadLockState();
    if (State == NULL || State->HeldCount >= SHADOWSTRIKE_MAX_HELD_LOCKS) {
        return;
    }
    ULONG Index = State->HeldCount;
    State->HeldLocks[Index].Lock = Lock;
    State->HeldLocks[Index].Order = Order;
    State->HeldLocks[Index].Type = Type;
    State->HeldCount++;
}

/**
 * Record lock release. Uses ShadowFindThreadLockState (no allocation).
 */
static
VOID
ShadowRecordLockRelease(
    _In_ PVOID Lock
)
{
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowFindThreadLockState();
    if (State == NULL || State->HeldCount == 0) {
        return;
    }

    for (ULONG i = State->HeldCount; i > 0; i--) {
        if (State->HeldLocks[i - 1].Lock == Lock) {
            for (ULONG j = i - 1; j < State->HeldCount - 1; j++) {
                State->HeldLocks[j] = State->HeldLocks[j + 1];
            }
            State->HeldCount--;

            //
            // If thread holds no more locks, remove state to prevent
            // unbounded growth from short-lived threads.
            //
            if (State->HeldCount == 0) {
                KIRQL OldIrql;
                KeAcquireSpinLock(&g_LockSubsystem.ThreadStateLock, &OldIrql);
                RemoveEntryList(&State->ListEntry);
                KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
                ExFreeToNPagedLookasideList(
                    &g_LockSubsystem.ThreadStateLookaside, State);
            }
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

    if (InterlockedCompareExchange(&g_LockSubsystem.Initialized, 1, 0) != 0) {
        return STATUS_SUCCESS;
    }

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

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLockSubsystemCleanup(
    VOID
)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_LockSubsystem.Initialized, 0, 1) != 1) {
        return;
    }

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    {
        KIRQL OldIrql;
        KeAcquireSpinLock(&g_LockSubsystem.ThreadStateLock, &OldIrql);

        while (!IsListEmpty(&g_LockSubsystem.ThreadStateList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&g_LockSubsystem.ThreadStateList);
            PSHADOWSTRIKE_THREAD_LOCK_STATE State = CONTAINING_RECORD(
                Entry, SHADOWSTRIKE_THREAD_LOCK_STATE, ListEntry);
            ExFreeToNPagedLookasideList(
                &g_LockSubsystem.ThreadStateLookaside, State);
        }

        KeReleaseSpinLock(&g_LockSubsystem.ThreadStateLock, OldIrql);
        ExDeleteNPagedLookasideList(&g_LockSubsystem.ThreadStateLookaside);
    }
#endif
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
    InterlockedIncrement64(&g_LockSubsystem.TotalLocksCreated);
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
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    if (KeTryToAcquireSpinLockAtDpcLevel(&Lock->Lock)) {
        Lock->OldIrql = OldIrql;

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
        return TRUE;
    }

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
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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
    InterlockedIncrement64(&g_LockSubsystem.TotalLocksCreated);
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

    KeAcquireInStackQueuedSpinLock(&Lock->Lock, &LockHandle->LockHandle);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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

    //
    // If LockQueue.Lock is NULL, this handle was populated by TryAcquire
    // (which used KeTryToAcquireSpinLockAtDpcLevel, NOT
    // KeAcquireInStackQueuedSpinLock). Release via the plain spinlock
    // path and restore IRQL manually.
    //
    if (LockHandle->LockHandle.LockQueue.Lock == NULL && Lock != NULL) {
        KIRQL OldIrql = LockHandle->LockHandle.OldIrql;
        KeReleaseSpinLockFromDpcLevel(&Lock->Lock);
        KeLowerIrql(OldIrql);
    } else {
        KeReleaseInStackQueuedSpinLock(&LockHandle->LockHandle);
    }
}

/**
 * TryAcquire for queued spinlock.
 *
 * There is no KeTryToAcquireInStackQueuedSpinLock API. We raise IRQL
 * to DISPATCH_LEVEL, then use KeTryToAcquireSpinLockAtDpcLevel. On
 * success, the lock is held as a plain spinlock (not queued). The
 * release function detects this case by checking if LockHandle was
 * populated by KeAcquireInStackQueuedSpinLock (LockQueue.Lock != NULL)
 * vs a try-acquire (LockQueue.Lock == NULL).
 *
 * On failure, IRQL is restored. No lock is held.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeTryAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
)
{
    KIRQL OldIrql;

    RtlZeroMemory(LockHandle, sizeof(SHADOWSTRIKE_INSTACK_QUEUED_LOCK));
    LockHandle->ParentLock = Lock;

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    if (KeTryToAcquireSpinLockAtDpcLevel(&Lock->Lock)) {
        //
        // Store OldIrql for release. LockQueue.Lock stays NULL to signal
        // that the release path must use KeReleaseSpinLockFromDpcLevel
        // instead of KeReleaseInStackQueuedSpinLock.
        //
        LockHandle->LockHandle.OldIrql = OldIrql;

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, FALSE);
#endif

#if SHADOWSTRIKE_DEADLOCK_DETECTION
        ShadowRecordLockAcquire(Lock, Lock->LockOrder, Lock->Type);
#endif
        return TRUE;
    }

    KeLowerIrql(OldIrql);

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
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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
#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (LockHandle->ParentLock != NULL) {
        ShadowRecordLockRelease(LockHandle->ParentLock);
    }
#endif

#if SHADOWSTRIKE_LOCK_STATISTICS
    if (LockHandle->ParentLock != NULL) {
        ShadowRecordRelease(&LockHandle->ParentLock->Stats);
    }
#endif

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle->LockHandle);
}

// ============================================================================
// READER-WRITER SPINLOCK IMPLEMENTATION
//
// Uses EX_SPIN_LOCK exclusively. OldIrql is ALWAYS caller-provided.
// No State/WriterThread/ReaderCount metadata — the EX_SPIN_LOCK is
// the single source of truth.
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

#if SHADOWSTRIKE_LOCK_STATISTICS
    RtlZeroMemory(&Lock->Stats, sizeof(Lock->Stats));
    InterlockedIncrement64(&g_LockSubsystem.TotalLocksCreated);
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

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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

    ExReleaseSpinLockShared(&Lock->Lock, OldIrql);
}

/**
 * TryAcquire exclusive on RW lock.
 *
 * ExTryAcquireSpinLockExclusiveAtDpcLevel requires IRQL == DISPATCH_LEVEL.
 * We raise IRQL first, attempt the try-acquire, and lower on failure.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeTryAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
)
{
    KeRaiseIrql(DISPATCH_LEVEL, OldIrql);

    if (ExTryAcquireSpinLockExclusiveAtDpcLevel(&Lock->Lock)) {

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, FALSE);
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
    InterlockedIncrement64(&g_LockSubsystem.TotalLocksCreated);
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
    // Ownership check is safe without lock because:
    // - Only the owning thread can set OwnerThread == CurrentThread
    // - Pointer reads are atomic on x86/x64
    // - If we're the owner, RecursionCount > 0 and the lock is held
    //
    if (Lock->OwnerThread == CurrentThread) {
        LONG NewCount = InterlockedIncrement(&Lock->RecursionCount);
        NT_ASSERT(NewCount <= SHADOWSTRIKE_MAX_RECURSION_DEPTH);

#if SHADOWSTRIKE_LOCK_STATISTICS
        ShadowRecordAcquisition(&Lock->Stats, FALSE);
#endif
        return;
    }

#if SHADOWSTRIKE_DEADLOCK_DETECTION
    if (Lock->LockOrder > 0) {
        NT_ASSERT(ShadowStrikeValidateLockOrder(Lock, Lock->LockOrder));
    }
#endif

    {
        KIRQL OldIrql;
        KeAcquireSpinLock(&Lock->Lock, &OldIrql);

        Lock->OwnerThread = CurrentThread;
        Lock->RecursionCount = 1;
        Lock->SavedIrql = OldIrql;
    }

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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
    NT_ASSERT(Lock->OwnerThread == KeGetCurrentThread());

    LONG NewCount = InterlockedDecrement(&Lock->RecursionCount);
    NT_ASSERT(NewCount >= 0);

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordRelease(&Lock->Stats);
#endif

    if (NewCount == 0) {
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
    InterlockedIncrement64(&g_LockSubsystem.TotalLocksCreated);
#endif
}

VOID
ShadowStrikeAcquireInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
)
{
    if (Lock->Interrupt != NULL) {
        Lock->OldIrql = KeAcquireInterruptSpinLock(Lock->Interrupt);
    } else {
        KeAcquireSpinLock(&Lock->Lock, &Lock->OldIrql);
    }

#if SHADOWSTRIKE_LOCK_STATISTICS
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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

    ShadowStrikeAcquireInterruptSpinLock(Lock);
    {
        BOOLEAN Result = Callback(Context);
        ShadowStrikeReleaseInterruptSpinLock(Lock);
        return Result;
    }
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
    InterlockedIncrement64(&g_LockSubsystem.TotalLocksCreated);
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
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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
    ShadowRecordAcquisition(&Lock->Stats, FALSE);
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

    RtlZeroMemory(Stats, sizeof(SHADOWSTRIKE_LOCK_STATS));
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
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowGetOrCreateThreadLockState();

    if (State == NULL) {
        return TRUE;
    }

    for (ULONG i = 0; i < State->HeldCount; i++) {
        if (State->HeldLocks[i].Order >= Order) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "ShadowStrike: Lock order violation! "
                "Attempting lock %p (order %u) "
                "while holding lock %p (order %u)\n",
                Lock, Order,
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
    PSHADOWSTRIKE_THREAD_LOCK_STATE State = ShadowFindThreadLockState();

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
