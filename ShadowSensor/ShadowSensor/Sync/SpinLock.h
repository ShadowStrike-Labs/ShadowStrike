/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE SPINLOCK UTILITIES
 * ============================================================================
 *
 * @file SpinLock.h
 * @brief Enterprise-grade spinlock primitives for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level synchronization with:
 * - Basic spinlocks with IRQL management
 * - Queued spinlocks for reduced cache-line bouncing
 * - Reader-writer spinlocks for read-heavy workloads
 * - Recursive spinlocks for re-entrant code paths
 * - In-stack queued spinlocks for minimal allocation
 * - Interrupt-safe spinlock variants
 * - Lock statistics and contention monitoring
 * - Deadlock detection in checked builds
 * - IRQL validation and tracking
 *
 * Performance Guarantees:
 * - Queued locks scale to high core counts (64+ CPUs)
 * - Reader-writer locks allow concurrent readers
 * - Statistics have minimal overhead when disabled
 * - All locks are cache-line aligned to prevent false sharing
 *
 * Security Guarantees:
 * - IRQL is always properly saved and restored
 * - Lock ordering validation prevents deadlocks
 * - Debug builds detect common lock misuse patterns
 * - All operations are interrupt-safe when required
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (thread-safe data structures)
 * - T1106: Native API (safe kernel synchronization)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

/**
 * @brief Enable lock statistics collection (performance impact)
 */
#ifndef SHADOWSTRIKE_LOCK_STATISTICS
#if DBG
#define SHADOWSTRIKE_LOCK_STATISTICS 1
#else
#define SHADOWSTRIKE_LOCK_STATISTICS 0
#endif
#endif

/**
 * @brief Enable deadlock detection (debug builds only)
 */
#ifndef SHADOWSTRIKE_DEADLOCK_DETECTION
#if DBG
#define SHADOWSTRIKE_DEADLOCK_DETECTION 1
#else
#define SHADOWSTRIKE_DEADLOCK_DETECTION 0
#endif
#endif

/**
 * @brief Maximum spin count before yielding
 */
#define SHADOWSTRIKE_SPIN_COUNT_MAX         4000

/**
 * @brief Spin count for try-acquire operations
 */
#define SHADOWSTRIKE_SPIN_COUNT_TRY         100

/**
 * @brief Maximum lock nesting depth for recursive locks
 */
#define SHADOWSTRIKE_MAX_RECURSION_DEPTH    16

/**
 * @brief Maximum tracked locks for deadlock detection
 */
#define SHADOWSTRIKE_MAX_HELD_LOCKS         32

// ============================================================================
// POOL TAGS
// ============================================================================

#define SHADOW_LOCK_TAG     'kLsS'  // SsLk - ShadowStrike Lock
#define SHADOW_RWLOCK_TAG   'wRsS'  // SsRw - ShadowStrike RW Lock
#define SHADOW_QLOCK_TAG    'qLsS'  // SsLq - ShadowStrike Queued Lock

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Lock type enumeration
 */
typedef enum _SHADOWSTRIKE_LOCK_TYPE {
    ShadowLockType_Spin = 0,            ///< Basic spinlock
    ShadowLockType_SpinQueued,          ///< Queued spinlock (in-stack)
    ShadowLockType_SpinInStack,         ///< In-stack queued spinlock
    ShadowLockType_ReaderWriter,        ///< Reader-writer spinlock
    ShadowLockType_Recursive,           ///< Recursive spinlock
    ShadowLockType_Interrupt,           ///< Interrupt-safe spinlock
    ShadowLockType_Executive,           ///< Executive resource wrapper
    ShadowLockType_PushLock,            ///< Push lock wrapper
    ShadowLockType_Max
} SHADOWSTRIKE_LOCK_TYPE;

/**
 * @brief Lock state enumeration
 */
typedef enum _SHADOWSTRIKE_LOCK_STATE {
    ShadowLockState_Unlocked = 0,       ///< Lock is free
    ShadowLockState_Exclusive,          ///< Held exclusively
    ShadowLockState_Shared,             ///< Held shared (readers)
    ShadowLockState_Contended           ///< Lock is contended
} SHADOWSTRIKE_LOCK_STATE;

/**
 * @brief Lock acquisition mode
 */
typedef enum _SHADOWSTRIKE_LOCK_MODE {
    ShadowLockMode_Exclusive = 0,       ///< Exclusive access
    ShadowLockMode_Shared,              ///< Shared access (readers)
    ShadowLockMode_TryExclusive,        ///< Try exclusive (non-blocking)
    ShadowLockMode_TryShared            ///< Try shared (non-blocking)
} SHADOWSTRIKE_LOCK_MODE;

// ============================================================================
// LOCK STATISTICS
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

/**
 * @brief Lock statistics structure
 */
typedef struct _SHADOWSTRIKE_LOCK_STATS {
    /// Total acquisitions
    volatile LONG64 TotalAcquisitions;

    /// Total releases
    volatile LONG64 TotalReleases;

    /// Contention count (had to spin)
    volatile LONG64 ContentionCount;

    /// Total spin cycles
    volatile LONG64 TotalSpinCycles;

    /// Maximum spin cycles for single acquisition
    volatile LONG64 MaxSpinCycles;

    /// Failed try-acquire attempts
    volatile LONG64 TryFailures;

    /// Current holder thread (debug)
    HANDLE OwnerThread;

    /// Acquisition timestamp
    LARGE_INTEGER AcquireTime;

    /// Total hold time (100ns units)
    volatile LONG64 TotalHoldTime;

    /// Maximum hold time
    volatile LONG64 MaxHoldTime;

    /// Reader count (for RW locks)
    volatile LONG CurrentReaders;

    /// Peak reader count
    volatile LONG PeakReaders;

} SHADOWSTRIKE_LOCK_STATS, *PSHADOWSTRIKE_LOCK_STATS;

#endif // SHADOWSTRIKE_LOCK_STATISTICS

// ============================================================================
// BASIC SPINLOCK
// ============================================================================

/**
 * @brief Enterprise spinlock with IRQL tracking and statistics
 */
typedef struct _SHADOWSTRIKE_SPINLOCK {
    /// Kernel spinlock
    KSPIN_LOCK Lock;

    /// Saved IRQL
    KIRQL OldIrql;

    /// Lock type identifier
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Lock name for debugging
    PCSTR Name;

    /// Lock order for deadlock detection
    ULONG LockOrder;

    /// Padding for cache alignment
    UCHAR Padding[3];

#if SHADOWSTRIKE_LOCK_STATISTICS
    /// Lock statistics
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif

} SHADOWSTRIKE_SPINLOCK, *PSHADOWSTRIKE_SPINLOCK;

/**
 * @brief Legacy lock type for backward compatibility
 */
typedef SHADOWSTRIKE_SPINLOCK SHADOWSTRIKE_LOCK;
typedef PSHADOWSTRIKE_SPINLOCK PSHADOWSTRIKE_LOCK;

// ============================================================================
// QUEUED SPINLOCK
// ============================================================================

/**
 * @brief Queued spinlock for high-contention scenarios
 *
 * Uses in-stack queue nodes to reduce cache-line bouncing
 * on systems with many processors.
 */
typedef struct _SHADOWSTRIKE_QUEUED_SPINLOCK {
    /// Kernel queued spinlock
    KSPIN_LOCK_QUEUE LockQueue;

    /// Actual spinlock
    KSPIN_LOCK Lock;

    /// Lock type
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Lock name
    PCSTR Name;

    /// Lock order
    ULONG LockOrder;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif

} SHADOWSTRIKE_QUEUED_SPINLOCK, *PSHADOWSTRIKE_QUEUED_SPINLOCK;

/**
 * @brief In-stack queued lock handle
 */
typedef struct _SHADOWSTRIKE_INSTACK_QUEUED_LOCK {
    /// Lock queue handle
    KLOCK_QUEUE_HANDLE LockHandle;

    /// Reference to parent lock
    PSHADOWSTRIKE_QUEUED_SPINLOCK ParentLock;

#if SHADOWSTRIKE_LOCK_STATISTICS
    /// Acquisition start time
    LARGE_INTEGER StartTime;
    /// Spin count during acquisition
    ULONG SpinCount;
#endif

} SHADOWSTRIKE_INSTACK_QUEUED_LOCK, *PSHADOWSTRIKE_INSTACK_QUEUED_LOCK;

// ============================================================================
// READER-WRITER SPINLOCK
// ============================================================================

/**
 * @brief Reader-writer spinlock for read-heavy workloads
 *
 * Allows multiple concurrent readers or single exclusive writer.
 * Uses EX_SPIN_LOCK for optimal performance on modern Windows.
 */
typedef struct _SHADOWSTRIKE_RWSPINLOCK {
    /// Executive spinlock (supports reader-writer semantics)
    EX_SPIN_LOCK Lock;

    /// Lock type
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Lock name
    PCSTR Name;

    /// Lock order
    ULONG LockOrder;

    /// Current state
    volatile SHADOWSTRIKE_LOCK_STATE State;

    /// Writer thread (when held exclusively)
    volatile HANDLE WriterThread;

    /// Reader count
    volatile LONG ReaderCount;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif

} SHADOWSTRIKE_RWSPINLOCK, *PSHADOWSTRIKE_RWSPINLOCK;

/**
 * @brief RW lock guard for automatic IRQL restore
 */
typedef struct _SHADOWSTRIKE_RWLOCK_GUARD {
    /// Reference to RW lock
    PSHADOWSTRIKE_RWSPINLOCK Lock;

    /// Saved IRQL
    KIRQL OldIrql;

    /// Acquisition mode
    SHADOWSTRIKE_LOCK_MODE Mode;

    /// Is lock held
    BOOLEAN Held;

#if SHADOWSTRIKE_LOCK_STATISTICS
    LARGE_INTEGER StartTime;
#endif

} SHADOWSTRIKE_RWLOCK_GUARD, *PSHADOWSTRIKE_RWLOCK_GUARD;

// ============================================================================
// RECURSIVE SPINLOCK
// ============================================================================

/**
 * @brief Recursive spinlock allowing re-entrant acquisition
 *
 * Tracks ownership and recursion depth. Use sparingly as
 * recursive locks can mask design issues.
 */
typedef struct _SHADOWSTRIKE_RECURSIVE_SPINLOCK {
    /// Underlying spinlock
    KSPIN_LOCK Lock;

    /// Owner thread
    volatile PKTHREAD OwnerThread;

    /// Recursion depth
    volatile LONG RecursionCount;

    /// Saved IRQL (from first acquisition)
    KIRQL SavedIrql;

    /// Lock type
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Lock name
    PCSTR Name;

    /// Lock order
    ULONG LockOrder;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif

} SHADOWSTRIKE_RECURSIVE_SPINLOCK, *PSHADOWSTRIKE_RECURSIVE_SPINLOCK;

// ============================================================================
// INTERRUPT SPINLOCK
// ============================================================================

/**
 * @brief Interrupt-safe spinlock for use with interrupt objects
 *
 * Synchronizes with interrupt service routines.
 */
typedef struct _SHADOWSTRIKE_INTERRUPT_SPINLOCK {
    /// Kernel interrupt spinlock
    KSPIN_LOCK Lock;

    /// Associated interrupt object (optional)
    PKINTERRUPT Interrupt;

    /// Saved IRQL
    KIRQL OldIrql;

    /// Lock type
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Lock name
    PCSTR Name;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif

} SHADOWSTRIKE_INTERRUPT_SPINLOCK, *PSHADOWSTRIKE_INTERRUPT_SPINLOCK;

// ============================================================================
// PUSH LOCK WRAPPER
// ============================================================================

/**
 * @brief Push lock wrapper for IRQL < DISPATCH_LEVEL operations
 *
 * More efficient than spinlocks when blocking is acceptable.
 * Cannot be used at DISPATCH_LEVEL.
 */
typedef struct _SHADOWSTRIKE_PUSHLOCK {
    /// Executive push lock
    EX_PUSH_LOCK Lock;

    /// Lock type
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Lock name
    PCSTR Name;

    /// Lock order
    ULONG LockOrder;

    /// Is initialized
    BOOLEAN Initialized;

#if SHADOWSTRIKE_LOCK_STATISTICS
    SHADOWSTRIKE_LOCK_STATS Stats;
#endif

} SHADOWSTRIKE_PUSHLOCK, *PSHADOWSTRIKE_PUSHLOCK;

// ============================================================================
// LOCK GUARD (RAII-style for C)
// ============================================================================

/**
 * @brief Lock guard for scoped locking
 */
typedef struct _SHADOWSTRIKE_LOCK_GUARD {
    /// Lock pointer
    PVOID Lock;

    /// Lock type
    SHADOWSTRIKE_LOCK_TYPE Type;

    /// Saved IRQL
    KIRQL OldIrql;

    /// Is lock currently held
    BOOLEAN Held;

    /// Mode (exclusive/shared)
    SHADOWSTRIKE_LOCK_MODE Mode;

} SHADOWSTRIKE_LOCK_GUARD, *PSHADOWSTRIKE_LOCK_GUARD;

// ============================================================================
// INITIALIZATION FUNCTIONS
// ============================================================================

/**
 * @brief Initialize the spinlock subsystem.
 *
 * Sets up deadlock detection and statistics infrastructure.
 * Must be called during driver initialization.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeLockSubsystemInitialize(
    VOID
    );

/**
 * @brief Cleanup the spinlock subsystem.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLockSubsystemCleanup(
    VOID
    );

// ============================================================================
// BASIC SPINLOCK API
// ============================================================================

/**
 * @brief Initialize a spinlock.
 *
 * @param Lock      Spinlock to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeSpinLock(
    _Out_ PSHADOWSTRIKE_SPINLOCK Lock
    );

/**
 * @brief Initialize a named spinlock with lock order.
 *
 * @param Lock      Spinlock to initialize
 * @param Name      Lock name for debugging
 * @param LockOrder Lock order for deadlock detection
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeSpinLockEx(
    _Out_ PSHADOWSTRIKE_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

/**
 * @brief Acquire spinlock, raising IRQL to DISPATCH_LEVEL.
 *
 * @param Lock      Spinlock to acquire
 *
 * @irql <= DISPATCH_LEVEL
 * @irql_out DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_lock_(Lock->Lock)
VOID
ShadowStrikeAcquireSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

/**
 * @brief Release spinlock, restoring previous IRQL.
 *
 * @param Lock      Spinlock to release
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(Lock->Lock)
VOID
ShadowStrikeReleaseSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

/**
 * @brief Try to acquire spinlock without blocking.
 *
 * @param Lock      Spinlock to acquire
 *
 * @return TRUE if lock acquired, FALSE if contended
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireSpinLock(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

/**
 * @brief Acquire spinlock at current IRQL (must be DISPATCH_LEVEL).
 *
 * @param Lock      Spinlock to acquire
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
_Acquires_lock_(Lock->Lock)
VOID
ShadowStrikeAcquireSpinLockAtDpcLevel(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

/**
 * @brief Release spinlock without lowering IRQL.
 *
 * @param Lock      Spinlock to release
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(Lock->Lock)
VOID
ShadowStrikeReleaseSpinLockFromDpcLevel(
    _Inout_ PSHADOWSTRIKE_SPINLOCK Lock
    );

// ============================================================================
// QUEUED SPINLOCK API
// ============================================================================

/**
 * @brief Initialize a queued spinlock.
 *
 * @param Lock      Queued spinlock to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeQueuedSpinLock(
    _Out_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock
    );

/**
 * @brief Initialize a named queued spinlock.
 *
 * @param Lock      Queued spinlock to initialize
 * @param Name      Lock name for debugging
 * @param LockOrder Lock order for deadlock detection
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeQueuedSpinLockEx(
    _Out_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

/**
 * @brief Acquire queued spinlock using in-stack queue handle.
 *
 * @param Lock          Queued spinlock to acquire
 * @param LockHandle    In-stack queue handle (must be on stack)
 *
 * @irql <= DISPATCH_LEVEL
 * @irql_out DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

/**
 * @brief Release queued spinlock.
 *
 * @param LockHandle    In-stack queue handle from acquire
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

/**
 * @brief Try to acquire queued spinlock.
 *
 * @param Lock          Queued spinlock to acquire
 * @param LockHandle    In-stack queue handle
 *
 * @return TRUE if acquired, FALSE if contended
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireQueuedSpinLock(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

/**
 * @brief Acquire queued spinlock at DPC level.
 *
 * @param Lock          Queued spinlock to acquire
 * @param LockHandle    In-stack queue handle
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireQueuedSpinLockAtDpcLevel(
    _Inout_ PSHADOWSTRIKE_QUEUED_SPINLOCK Lock,
    _Out_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

/**
 * @brief Release queued spinlock without lowering IRQL.
 *
 * @param LockHandle    In-stack queue handle
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseQueuedSpinLockFromDpcLevel(
    _Inout_ PSHADOWSTRIKE_INSTACK_QUEUED_LOCK LockHandle
    );

// ============================================================================
// READER-WRITER SPINLOCK API
// ============================================================================

/**
 * @brief Initialize a reader-writer spinlock.
 *
 * @param Lock      RW spinlock to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRWSpinLock(
    _Out_ PSHADOWSTRIKE_RWSPINLOCK Lock
    );

/**
 * @brief Initialize a named reader-writer spinlock.
 *
 * @param Lock      RW spinlock to initialize
 * @param Name      Lock name for debugging
 * @param LockOrder Lock order for deadlock detection
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRWSpinLockEx(
    _Out_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

/**
 * @brief Acquire RW spinlock for exclusive (write) access.
 *
 * @param Lock      RW spinlock to acquire
 * @param OldIrql   Receives previous IRQL
 *
 * @irql <= DISPATCH_LEVEL
 * @irql_out DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

/**
 * @brief Release RW spinlock from exclusive access.
 *
 * @param Lock      RW spinlock to release
 * @param OldIrql   IRQL from acquire
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ KIRQL OldIrql
    );

/**
 * @brief Acquire RW spinlock for shared (read) access.
 *
 * @param Lock      RW spinlock to acquire
 * @param OldIrql   Receives previous IRQL
 *
 * @irql <= DISPATCH_LEVEL
 * @irql_out DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

/**
 * @brief Release RW spinlock from shared access.
 *
 * @param Lock      RW spinlock to release
 * @param OldIrql   IRQL from acquire
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _In_ KIRQL OldIrql
    );

/**
 * @brief Try to acquire RW spinlock exclusively.
 *
 * @param Lock      RW spinlock to acquire
 * @param OldIrql   Receives previous IRQL if successful
 *
 * @return TRUE if acquired, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireRWSpinLockExclusive(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

/**
 * @brief Try to acquire RW spinlock shared.
 *
 * @param Lock      RW spinlock to acquire
 * @param OldIrql   Receives previous IRQL if successful
 *
 * @return TRUE if acquired, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeTryAcquireRWSpinLockShared(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock,
    _Out_ PKIRQL OldIrql
    );

/**
 * @brief Upgrade shared lock to exclusive.
 *
 * @param Lock      RW spinlock to upgrade
 *
 * @return TRUE if upgraded, FALSE if failed (must release and re-acquire)
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
ShadowStrikeUpgradeRWSpinLock(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock
    );

/**
 * @brief Downgrade exclusive lock to shared.
 *
 * @param Lock      RW spinlock to downgrade
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeDowngradeRWSpinLock(
    _Inout_ PSHADOWSTRIKE_RWSPINLOCK Lock
    );

// ============================================================================
// RECURSIVE SPINLOCK API
// ============================================================================

/**
 * @brief Initialize a recursive spinlock.
 *
 * @param Lock      Recursive spinlock to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRecursiveSpinLock(
    _Out_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

/**
 * @brief Initialize a named recursive spinlock.
 *
 * @param Lock      Recursive spinlock to initialize
 * @param Name      Lock name for debugging
 * @param LockOrder Lock order for deadlock detection
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeRecursiveSpinLockEx(
    _Out_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

/**
 * @brief Acquire recursive spinlock.
 *
 * Can be called multiple times from same thread.
 *
 * @param Lock      Recursive spinlock to acquire
 *
 * @irql <= DISPATCH_LEVEL
 * @irql_out DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
VOID
ShadowStrikeAcquireRecursiveSpinLock(
    _Inout_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

/**
 * @brief Release recursive spinlock.
 *
 * Must be called same number of times as acquire.
 *
 * @param Lock      Recursive spinlock to release
 *
 * @irql DISPATCH_LEVEL
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRecursiveSpinLock(
    _Inout_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

/**
 * @brief Get current recursion depth.
 *
 * @param Lock      Recursive spinlock
 *
 * @return Current recursion count (0 if not held)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
ShadowStrikeGetRecursionDepth(
    _In_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

/**
 * @brief Check if current thread owns the recursive lock.
 *
 * @param Lock      Recursive spinlock
 *
 * @return TRUE if current thread owns the lock
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsRecursiveLockOwned(
    _In_ PSHADOWSTRIKE_RECURSIVE_SPINLOCK Lock
    );

// ============================================================================
// INTERRUPT SPINLOCK API
// ============================================================================

/**
 * @brief Initialize an interrupt spinlock.
 *
 * @param Lock      Interrupt spinlock to initialize
 * @param Interrupt Associated interrupt object (optional)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitializeInterruptSpinLock(
    _Out_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock,
    _In_opt_ PKINTERRUPT Interrupt
    );

/**
 * @brief Acquire interrupt spinlock.
 *
 * @param Lock      Interrupt spinlock to acquire
 *
 * @irql <= DIRQL
 */
VOID
ShadowStrikeAcquireInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
    );

/**
 * @brief Release interrupt spinlock.
 *
 * @param Lock      Interrupt spinlock to release
 */
VOID
ShadowStrikeReleaseInterruptSpinLock(
    _Inout_ PSHADOWSTRIKE_INTERRUPT_SPINLOCK Lock
    );

/**
 * @brief Synchronize callback with interrupt.
 *
 * @param Lock          Interrupt spinlock
 * @param Callback      Callback to execute
 * @param Context       Callback context
 *
 * @return TRUE if callback executed
 *
 * @irql <= DIRQL
 */
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

/**
 * @brief Initialize a push lock.
 *
 * @param Lock      Push lock to initialize
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeInitializePushLock(
    _Out_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

/**
 * @brief Initialize a named push lock.
 *
 * @param Lock      Push lock to initialize
 * @param Name      Lock name for debugging
 * @param LockOrder Lock order for deadlock detection
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeInitializePushLockEx(
    _Out_ PSHADOWSTRIKE_PUSHLOCK Lock,
    _In_ PCSTR Name,
    _In_ ULONG LockOrder
    );

/**
 * @brief Acquire push lock exclusively.
 *
 * @param Lock      Push lock to acquire
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeAcquirePushLockExclusive(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

/**
 * @brief Release push lock from exclusive access.
 *
 * @param Lock      Push lock to release
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleasePushLockExclusive(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

/**
 * @brief Acquire push lock shared.
 *
 * @param Lock      Push lock to acquire
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeAcquirePushLockShared(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

/**
 * @brief Release push lock from shared access.
 *
 * @param Lock      Push lock to release
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleasePushLockShared(
    _Inout_ PSHADOWSTRIKE_PUSHLOCK Lock
    );

// ============================================================================
// STATISTICS API
// ============================================================================

#if SHADOWSTRIKE_LOCK_STATISTICS

/**
 * @brief Get lock statistics.
 *
 * @param Lock      Any lock type
 * @param Type      Lock type
 * @param Stats     Receives statistics
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetLockStatistics(
    _In_ PVOID Lock,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type,
    _Out_ PSHADOWSTRIKE_LOCK_STATS Stats
    );

/**
 * @brief Reset lock statistics.
 *
 * @param Lock      Any lock type
 * @param Type      Lock type
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetLockStatistics(
    _Inout_ PVOID Lock,
    _In_ SHADOWSTRIKE_LOCK_TYPE Type
    );

#endif // SHADOWSTRIKE_LOCK_STATISTICS

// ============================================================================
// DEADLOCK DETECTION (Debug Only)
// ============================================================================

#if SHADOWSTRIKE_DEADLOCK_DETECTION

/**
 * @brief Validate lock ordering.
 *
 * @param Lock      Lock being acquired
 * @param Order     Lock order value
 *
 * @return TRUE if ordering is valid
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeValidateLockOrder(
    _In_ PVOID Lock,
    _In_ ULONG Order
    );

/**
 * @brief Dump current lock holdings.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeDumpHeldLocks(
    VOID
    );

#endif // SHADOWSTRIKE_DEADLOCK_DETECTION

// ============================================================================
// LEGACY COMPATIBILITY MACROS
// ============================================================================

/**
 * @brief Initialize lock (legacy name)
 */
#define ShadowStrikeInitializeLock(Lock) \
    ShadowStrikeInitializeSpinLock(Lock)

/**
 * @brief Acquire lock (legacy name)
 */
#define ShadowStrikeAcquireLock(Lock) \
    ShadowStrikeAcquireSpinLock(Lock)

/**
 * @brief Release lock (legacy name)
 */
#define ShadowStrikeReleaseLock(Lock) \
    ShadowStrikeReleaseSpinLock(Lock)

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if running at or above DISPATCH_LEVEL.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsAtDispatchLevel(
    VOID
    )
{
    return (KeGetCurrentIrql() >= DISPATCH_LEVEL);
}

/**
 * @brief Check if current IRQL allows paging.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsPagingAllowed(
    VOID
    )
{
    return (KeGetCurrentIrql() < DISPATCH_LEVEL);
}

/**
 * @brief Get current processor number.
 */
FORCEINLINE
ULONG
ShadowStrikeGetCurrentProcessor(
    VOID
    )
{
    return KeGetCurrentProcessorNumberEx(NULL);
}

/**
 * @brief Memory barrier.
 */
FORCEINLINE
VOID
ShadowStrikeMemoryBarrier(
    VOID
    )
{
    KeMemoryBarrier();
}

/**
 * @brief Yield processor during spin.
 */
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
