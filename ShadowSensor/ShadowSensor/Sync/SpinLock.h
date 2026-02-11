/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE SPINLOCK UTILITIES
 * ============================================================================
 *
 * @file SpinLock.h
 * @brief Enterprise-grade spinlock primitives for kernel-mode EDR operations.
 *
 * Provides synchronization primitives:
 * - Basic spinlocks with per-caller IRQL management
 * - Queued spinlocks for reduced cache-line bouncing
 * - Reader-writer spinlocks via EX_SPIN_LOCK
 * - Recursive spinlocks for re-entrant code paths
 * - Interrupt-safe spinlock variants
 * - Push lock wrappers with KeEnterCriticalRegion
 * - Lock statistics (debug builds only)
 * - Lock ordering validation (debug builds only)
 *
 * Design rules:
 * - OldIrql is ALWAYS per-caller (on stack or in out-param), NEVER in lock struct
 * - Push locks always bracket with KeEnterCriticalRegion/KeLeaveCriticalRegion
 * - Deadlock detection uses per-thread TLS slot, no global lock on hot path
 * - Statistics use interlocked ops only, no timers in release builds
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_SPINLOCK_H_
#define _SHADOWSTRIKE_SPINLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#ifndef SHADOWSTRIKE_LOCK_STATISTICS
#if DBG
#define SHADOWSTRIKE_LOCK_STATISTICS 1
#else
#define SHADOWSTRIKE_LOCK_STATISTICS 0
#endif
#endif

#ifndef SHADOWSTRIKE_DEADLOCK_DETECTION
#if DBG
#define SHADOWSTRIKE_DEADLOCK_DETECTION 1
#else
#define SHADOWSTRIKE_DEADLOCK_DETECTION 0
#endif
#endif

#define SHADOWSTRIKE_MAX_RECURSION_DEPTH    16
#define SHADOWSTRIKE_MAX_HELD_LOCKS         32

// ============================================================================
// POOL TAGS
// ============================================================================

#define SHADOW_LOCK_TAG     'kLsS'

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _SHADOWSTRIKE_LOCK_TYPE {
    ShadowLockType_Spin = 0,
    ShadowLockType_SpinQueued,
    ShadowLockType_ReaderWriter,
    ShadowLockType_Recursive,
    ShadowLockType_Interrupt,
    ShadowLockType_PushLock,
    ShadowLockType_Max
} SHADOWSTRIKE_LOCK_TYPE;

// ============================================================================
// LOCK STATISTICS (debug builds only)
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

typedef struct _SHADOWSTRIKE_LOCK_STATS {
    volatile LONG64 TotalAcquisitions;
    volatile LONG64 TotalReleases;
    volatile LONG64 ContentionCount;
    volatile LONG64 TotalSpinCycles;
    volatile LONG64 MaxSpinCycles;
    volatile LONG64 TryFailures;
    volatile LONG64 TotalHoldTime;
    volatile LONG64 MaxHoldTime;
    volatile LONG CurrentReaders;
    volatile LONG PeakReaders;
} SHADOWSTRIKE_LOCK_STATS, *PSHADOWSTRIKE_LOCK_STATS;

#endif

// ============================================================================
// BASIC SPINLOCK
// ============================================================================

/**
 * OldIrql is NOT stored in the lock. Callers use the dedicated
 * Acquire/Release pairs that pass OldIrql on the stack, or use
 * the wrapper which stores OldIrql in the lock for simple cases
 * where only one thread ever acquires (guaranteed by spin semantics).
 */
typedef struct _SHADOWSTRIKE_SPINLOCK {
    KSPIN_LOCK Lock;
    KIRQL OldIrql;
    SHADOWSTRIKE_LOCK_TYPE Type;
    PCSTR Name;
    ULONG LockOrder;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif
} SHADOWSTRIKE_SPINLOCK, *PSHADOWSTRIKE_SPINLOCK;

typedef SHADOWSTRIKE_SPINLOCK SHADOWSTRIKE_LOCK;
typedef PSHADOWSTRIKE_SPINLOCK PSHADOWSTRIKE_LOCK;

// ============================================================================
// QUEUED SPINLOCK
// ============================================================================

typedef struct _SHADOWSTRIKE_QUEUED_SPINLOCK {
    KSPIN_LOCK Lock;
    SHADOWSTRIKE_LOCK_TYPE Type;
    PCSTR Name;
    ULONG LockOrder;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif
} SHADOWSTRIKE_QUEUED_SPINLOCK, *PSHADOWSTRIKE_QUEUED_SPINLOCK;

typedef struct _SHADOWSTRIKE_INSTACK_QUEUED_LOCK {
    KLOCK_QUEUE_HANDLE LockHandle;
    PSHADOWSTRIKE_QUEUED_SPINLOCK ParentLock;
} SHADOWSTRIKE_INSTACK_QUEUED_LOCK, *PSHADOWSTRIKE_INSTACK_QUEUED_LOCK;

// ============================================================================
// READER-WRITER SPINLOCK
// ============================================================================

/**
 * Uses EX_SPIN_LOCK. OldIrql is always caller-provided (out-param).
 * No State/WriterThread/ReaderCount metadata — the EX_SPIN_LOCK itself
 * is the single source of truth. Upgrade/Downgrade are not supported
 * because EX_SPIN_LOCK does not provide atomic transitions.
 */
typedef struct _SHADOWSTRIKE_RWSPINLOCK {
    EX_SPIN_LOCK Lock;
    SHADOWSTRIKE_LOCK_TYPE Type;
    PCSTR Name;
    ULONG LockOrder;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif
} SHADOWSTRIKE_RWSPINLOCK, *PSHADOWSTRIKE_RWSPINLOCK;

// ============================================================================
// RECURSIVE SPINLOCK
// ============================================================================

typedef struct _SHADOWSTRIKE_RECURSIVE_SPINLOCK {
    KSPIN_LOCK Lock;
    volatile PKTHREAD OwnerThread;
    volatile LONG RecursionCount;
    KIRQL SavedIrql;
    SHADOWSTRIKE_LOCK_TYPE Type;
    PCSTR Name;
    ULONG LockOrder;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif
} SHADOWSTRIKE_RECURSIVE_SPINLOCK, *PSHADOWSTRIKE_RECURSIVE_SPINLOCK;

// ============================================================================
// INTERRUPT SPINLOCK
// ============================================================================

typedef struct _SHADOWSTRIKE_INTERRUPT_SPINLOCK {
    KSPIN_LOCK Lock;
    PKINTERRUPT Interrupt;
    KIRQL OldIrql;
    SHADOWSTRIKE_LOCK_TYPE Type;
    PCSTR Name;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif
} SHADOWSTRIKE_INTERRUPT_SPINLOCK, *PSHADOWSTRIKE_INTERRUPT_SPINLOCK;

// ============================================================================
// PUSH LOCK WRAPPER
// ============================================================================

typedef struct _SHADOWSTRIKE_PUSHLOCK {
    EX_PUSH_LOCK Lock;
    SHADOWSTRIKE_LOCK_TYPE Type;
    PCSTR Name;
    ULONG LockOrder;
    BOOLEAN Initialized;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif
} SHADOWSTRIKE_PUSHLOCK, *PSHADOWSTRIKE_PUSHLOCK;

// ============================================================================
// SUBSYSTEM INIT / CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeLockSubsystemInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLockSubsystemCleanup(
    VOID
    );

// ============================================================================
// BASIC SPINLOCK API
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeSpinLock(
    _Out_ PSHADOWSTRIKE_SPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeSpinLockEx(
    _Out_ PSHADOWSTRIKE_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_lock_(Lock->Lock)
VOID
ShadowStrikeAcquireSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(Lock->Lock)
VOID
ShadowStrikeReleaseSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

_IRQL_requires_(DISPATCH_LEVEL)
_Acquires_lock_(Lock->Lock)
VOID
ShadowStrikeAcquireSpinLockAtDpcLevel(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(Lock->Lock)
VOID
ShadowStrikeReleaseSpinLockFromDpcLevel(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

// ============================================================================
// QUEUED SPINLOCK API
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeQueuedSpinLock(
    _Out_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeQueuedSpinLockEx(
    _Out_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

/**
 * @brief Try to acquire queued spinlock without blocking.
 *
 * On success, IRQL is raised to DISPATCH_LEVEL.
 * On failure, IRQL is unchanged. The LockHandle is NOT valid on failure
 * and must NOT be passed to ReleaseQueuedSpinLock.
 *
 * Note: uses KeAcquireInStackQueuedSpinLockForDpc internally.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireQueuedSpinLockAtDpcLevel(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseQueuedSpinLockFromDpcLevel(
    _Inout_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

// ============================================================================
// READER-WRITER SPINLOCK API
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRWSpinLock(
    _Out_ PSHADOWSTRIKE_RWSPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRWSpinLockEx(
    _Out_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ KIRQL OldIrql
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ KIRQL OldIrql
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

// ============================================================================
// RECURSIVE SPINLOCK API
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRecursiveSpinLock(
    _Out_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRecursiveSpinLockEx(
    _Out_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRecursiveSpinLock(
    _Inout_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRecursiveSpinLock(
    _Inout_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
ShadowStrikeGetRecursionDepth(
    _In_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsRecursiveLockOwned(
    _In_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

// ============================================================================
// INTERRUPT SPINLOCK API
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeInterruptSpinLock(
    _Out_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock,
    _In_opt_ PKINTERRUPT Interrupt
    );

VOID
ShadowStrikeAcquireInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
    );

VOID
ShadowStrikeReleaseInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
    );

_Must_inspect_result_
BOOLEAN
ShadowStrikeSynchronizeWithInterrupt(
    _In_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock,
    _In_ PKSYNCHRONIZE_ROUTINE Callback,
    _In_opt_ PVOID Context
    );

// ============================================================================
// PUSH LOCK API
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeInitializePushLock(
    _Out_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeInitializePushLockEx(
    _Out_ PSHADOWSTRIKE_PUSHLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeAcquirePushLockExclusive(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleasePushLockExclusive(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeAcquirePushLockShared(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleasePushLockShared(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

// ============================================================================
// STATISTICS API (debug builds only)
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetLockStatistics(
    _In_ PVOID Lock,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type,
    _Out_ PSHADOWSTRIKE_LOCK_STATS Stats
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetLockStatistics(
    _Inout_ PVOID Lock,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type
    );

#endif

// ============================================================================
// DEADLOCK DETECTION (debug builds only)
// ============================================================================

#if SHADOWSTRIKE_DEADLOCK_DETECTION

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeValidateLockOrder(
    _In_ PVOID Lock,
    _In_ ULONG Order
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeDumpHeldLocks(
    VOID
    );

#endif

// ============================================================================
// LEGACY COMPATIBILITY MACROS
// ============================================================================

#define ShadowStrikeInitializeLock(Lock) \
    ShadowStrikeInitializeSpinLock(Lock)

#define ShadowStrikeAcquireLock(Lock) \
    ShadowStrikeAcquireSpinLock(Lock)

#define ShadowStrikeReleaseLock(Lock) \
    ShadowStrikeReleaseSpinLock(Lock)

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

FORCEINLINE
BOOLEAN
ShadowStrikeIsAtDispatchLevel(
    VOID
    )
{
    return (KeGetCurrentIrql() >= DISPATCH_LEVEL);
}

FORCEINLINE
BOOLEAN
ShadowStrikeIsPagingAllowed(
    VOID
    )
{
    return (KeGetCurrentIrql() < DISPATCH_LEVEL);
}

FORCEINLINE
ULONG
ShadowStrikeGetCurrentProcessor(
    VOID
    )
{
    return KeGetCurrentProcessorNumberEx(NULL);
}

FORCEINLINE
VOID
ShadowStrikeMemoryBarrier(
    VOID
    )
{
    KeMemoryBarrier();
}

FORCEINLINE
VOID
ShadowStrikeSpinYield(
    VOID
    )
{
    YieldProcessor();
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_SPINLOCK_H_
