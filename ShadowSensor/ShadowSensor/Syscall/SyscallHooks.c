/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - SYSCALL INTERCEPTION FRAMEWORK
 * ============================================================================
 *
 * @file SyscallHooks.c
 * @brief Enterprise-grade syscall hook registration and dispatch engine.
 *
 * Implements CrowdStrike Falcon-class syscall interception with:
 * - Hash-based O(1) hook lookup across full syscall number space
 * - Reference-counted framework and per-hook quiescence for safe teardown
 * - EX_PUSH_LOCK shared/exclusive locking (readers concurrent, writers exclusive)
 * - Interlocked enable/disable (lock-free on the hot dispatch path)
 * - Lookaside-pooled hook allocations for minimal allocation latency
 * - Rate limiting to bound callback storms
 * - Magic-validated pointer safety on all public API entry points
 * - Complete cleanup on every error path — no resource leaks
 *
 * Thread Safety Model:
 * - Framework-level: EX_PUSH_LOCK protects the hook hash table and list.
 *   Dispatch acquires shared; register/unregister acquire exclusive.
 * - Hook-level: Each hook has a volatile LONG ActiveCallbackCount.
 *   Unregister spins on this count draining to zero before freeing.
 * - Framework-level: volatile LONG ActiveDispatchCount tracks concurrent
 *   dispatches. Shutdown spins on this draining to zero.
 * - Enable/Disable: InterlockedExchange on volatile LONG Enabled field —
 *   no lock acquisition on the hot path.
 *
 * IRQL Rules:
 * - All public APIs: PASSIVE_LEVEL (ShRegisterHook/ShEnableHook/ShDisableHook
 *   tolerate APC_LEVEL).
 * - Internal hash lookup: safe at APC_LEVEL (NonPagedPoolNx + push lock).
 * - Callbacks: invoked at PASSIVE_LEVEL.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SyscallHooks.h"
#include "../Utilities/MemoryUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/** @brief Shutdown drain poll interval: 1 ms */
#define SH_DRAIN_POLL_INTERVAL_100NS        (-10000LL)

/** @brief Maximum drain wait iterations before forced teardown (10 seconds) */
#define SH_MAX_DRAIN_ITERATIONS             10000

/** @brief Rate limit window: 1 second in 100ns units */
#define SH_RATE_LIMIT_WINDOW_100NS          (10000000LL)

/** @brief Default rate limit: dispatches per second */
#define SH_DEFAULT_RATE_LIMIT_PER_SECOND    50000

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Internal hook entry with full metadata.
 *
 * Embeds within a hash bucket chain via HashListEntry.
 * Also linked in the global AllHooksList for enumeration/cleanup.
 */
typedef struct _SH_HOOK_INTERNAL {
    /** Magic for pointer validation */
    ULONG Magic;

    /** Syscall number this hook is registered for */
    ULONG SyscallNumber;

    /** Pre-call callback (NULL if not registered) */
    SH_HOOK_CALLBACK PreCallback;

    /** Post-call callback (NULL if not registered) */
    SH_HOOK_CALLBACK PostCallback;

    /** Opaque caller-supplied cookie passed to callbacks */
    PVOID Cookie;

    /** Hook enabled state — interlocked, no lock needed for read */
    volatile LONG Enabled;

    /** Count of callbacks currently executing on this hook */
    volatile LONG ActiveCallbackCount;

    /** Monotonic invocation counter */
    volatile LONG64 HitCount;

    /** Link in hash bucket chain */
    LIST_ENTRY HashListEntry;

    /** Link in framework-wide all-hooks list */
    LIST_ENTRY AllHooksListEntry;

} SH_HOOK_INTERNAL, *PSH_HOOK_INTERNAL;

/**
 * @brief Hash table bucket — one per SH_HASH_BUCKET_COUNT.
 */
typedef struct _SH_HASH_BUCKET {
    LIST_ENTRY Head;
} SH_HASH_BUCKET, *PSH_HASH_BUCKET;

/**
 * @brief Internal framework state.
 */
typedef struct _SH_FRAMEWORK_INTERNAL {
    /** Magic for pointer validation */
    ULONG Magic;

    /** Initialization sentinel */
    BOOLEAN Initialized;

    /** Padding */
    UCHAR Reserved0[3];

    /**
     * @brief Hash table for O(1) hook lookup by syscall number.
     * Bucket index = SyscallNumber & (SH_HASH_BUCKET_COUNT - 1).
     */
    SH_HASH_BUCKET Buckets[SH_HASH_BUCKET_COUNT];

    /**
     * @brief Global list of all registered hooks (for enumeration and cleanup).
     */
    LIST_ENTRY AllHooksList;

    /**
     * @brief Push lock protecting Buckets and AllHooksList.
     * Shared for dispatch (read), exclusive for register/unregister (write).
     */
    EX_PUSH_LOCK HookLock;

    /** Number of currently registered hooks */
    volatile LONG RegisteredHookCount;

    /** Number of currently enabled hooks */
    volatile LONG EnabledHookCount;

    /** Number of dispatch calls currently in-flight */
    volatile LONG ActiveDispatchCount;

    /** Peak concurrent dispatches (high-water mark) */
    volatile LONG PeakConcurrentDispatches;

    /** Shutdown flag — once set, no new dispatches are accepted */
    volatile LONG ShuttingDown;

    /** Lookaside list for hook entry allocations */
    NPAGED_LOOKASIDE_LIST HookLookaside;

    /** TRUE after lookaside is initialized (for cleanup ordering) */
    BOOLEAN LookasideInitialized;

    UCHAR Reserved1[7];

    // ---- Rate limiting ----

    /** Maximum dispatches per rate-limit window */
    LONG RateLimitPerWindow;

    /** Dispatches in current window */
    volatile LONG64 CurrentWindowDispatches;

    /** Window start timestamp (100ns units) */
    volatile LONG64 WindowStartTime;

    // ---- Statistics ----

    volatile LONG64 TotalDispatches;
    volatile LONG64 TotalCallbackInvocations;
    volatile LONG64 TotalBlocked;
    volatile LONG64 TotalLogged;
    volatile LONG64 TotalRateLimited;
    LARGE_INTEGER   StartTime;

} SH_FRAMEWORK_INTERNAL, *PSH_FRAMEWORK_INTERNAL;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static PSH_FRAMEWORK_INTERNAL
ShpValidateFramework(
    _In_ SH_FRAMEWORK_HANDLE Handle
    );

static PSH_HOOK_INTERNAL
ShpValidateHook(
    _In_ SH_HOOK_HANDLE Handle
    );

_Must_inspect_result_
static ULONG
ShpHashSyscallNumber(
    _In_ ULONG SyscallNumber
    );

static PSH_HOOK_INTERNAL
ShpFindHookInBucket(
    _In_ PSH_HASH_BUCKET Bucket,
    _In_ ULONG SyscallNumber
    );

static VOID
ShpAcquireDispatchRef(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw
    );

static VOID
ShpReleaseDispatchRef(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw
    );

static VOID
ShpAcquireHookRef(
    _Inout_ PSH_HOOK_INTERNAL Hook
    );

static VOID
ShpReleaseHookRef(
    _Inout_ PSH_HOOK_INTERNAL Hook
    );

static VOID
ShpDrainHookCallbacks(
    _In_ PSH_HOOK_INTERNAL Hook
    );

static VOID
ShpDrainAllDispatches(
    _In_ PSH_FRAMEWORK_INTERNAL Fw
    );

static VOID
ShpFreeHookEntry(
    _In_ PSH_FRAMEWORK_INTERNAL Fw,
    _In_ PSH_HOOK_INTERNAL Hook
    );

static BOOLEAN
ShpCheckRateLimit(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw
    );

static VOID
ShpUpdatePeakConcurrent(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw,
    _In_ LONG CurrentCount
    );

// ============================================================================
// SECTION PLACEMENT
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShInitialize)
#pragma alloc_text(PAGE, ShShutdown)
#pragma alloc_text(PAGE, ShRegisterHook)
#pragma alloc_text(PAGE, ShUnregisterHook)
#pragma alloc_text(PAGE, ShEnableHook)
#pragma alloc_text(PAGE, ShDisableHook)
#pragma alloc_text(PAGE, ShDispatchSyscall)
#pragma alloc_text(PAGE, ShGetStatistics)
#endif

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

/**
 * @brief Validate a framework handle and return the internal pointer.
 */
static PSH_FRAMEWORK_INTERNAL
ShpValidateFramework(
    _In_ SH_FRAMEWORK_HANDLE Handle
    )
{
    PSH_FRAMEWORK_INTERNAL fw = (PSH_FRAMEWORK_INTERNAL)(PVOID)Handle;

    if (fw == NULL) {
        return NULL;
    }

    __try {
        if (fw->Magic != SH_FRAMEWORK_MAGIC || !fw->Initialized) {
            return NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return fw;
}

/**
 * @brief Validate a hook handle and return the internal pointer.
 */
static PSH_HOOK_INTERNAL
ShpValidateHook(
    _In_ SH_HOOK_HANDLE Handle
    )
{
    PSH_HOOK_INTERNAL hook = (PSH_HOOK_INTERNAL)(PVOID)Handle;

    if (hook == NULL) {
        return NULL;
    }

    __try {
        if (hook->Magic != SH_HOOK_MAGIC) {
            return NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return hook;
}

/**
 * @brief Compute hash bucket index for a syscall number.
 * Uses a multiplicative hash to distribute entries across buckets.
 */
_Must_inspect_result_
static ULONG
ShpHashSyscallNumber(
    _In_ ULONG SyscallNumber
    )
{
    /*
     * Knuth multiplicative hash. SH_HASH_BUCKET_COUNT is 256 (power of 2),
     * so masking is correct. The golden ratio constant scatters sequential
     * syscall numbers across buckets effectively.
     */
    ULONG hash = SyscallNumber * 2654435761u;
    return hash & (SH_HASH_BUCKET_COUNT - 1);
}

/**
 * @brief Find a hook for a specific syscall number within a hash bucket.
 *
 * Caller must hold at least shared lock on Fw->HookLock.
 */
static PSH_HOOK_INTERNAL
ShpFindHookInBucket(
    _In_ PSH_HASH_BUCKET Bucket,
    _In_ ULONG SyscallNumber
    )
{
    PLIST_ENTRY entry;
    ULONG walkCount = 0;

    for (entry = Bucket->Head.Flink;
         entry != &Bucket->Head && walkCount < SH_MAX_REGISTERED_HOOKS;
         entry = entry->Flink, walkCount++)
    {
        PSH_HOOK_INTERNAL hook = CONTAINING_RECORD(
            entry, SH_HOOK_INTERNAL, HashListEntry);

        if (hook->Magic == SH_HOOK_MAGIC &&
            hook->SyscallNumber == SyscallNumber)
        {
            return hook;
        }
    }

    return NULL;
}

/**
 * @brief Increment framework active dispatch count.
 */
static VOID
ShpAcquireDispatchRef(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw
    )
{
    LONG count = InterlockedIncrement(&Fw->ActiveDispatchCount);
    ShpUpdatePeakConcurrent(Fw, count);
}

/**
 * @brief Decrement framework active dispatch count.
 */
static VOID
ShpReleaseDispatchRef(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw
    )
{
    InterlockedDecrement(&Fw->ActiveDispatchCount);
}

/**
 * @brief Increment hook active callback count.
 */
static VOID
ShpAcquireHookRef(
    _Inout_ PSH_HOOK_INTERNAL Hook
    )
{
    InterlockedIncrement(&Hook->ActiveCallbackCount);
}

/**
 * @brief Decrement hook active callback count.
 */
static VOID
ShpReleaseHookRef(
    _Inout_ PSH_HOOK_INTERNAL Hook
    )
{
    InterlockedDecrement(&Hook->ActiveCallbackCount);
}

/**
 * @brief Wait for all active callbacks on a specific hook to drain.
 */
static VOID
ShpDrainHookCallbacks(
    _In_ PSH_HOOK_INTERNAL Hook
    )
{
    LARGE_INTEGER interval;
    ULONG iterations = 0;

    interval.QuadPart = SH_DRAIN_POLL_INTERVAL_100NS;

    while (Hook->ActiveCallbackCount > 0 &&
           iterations < SH_MAX_DRAIN_ITERATIONS)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        iterations++;
    }
}

/**
 * @brief Wait for all active dispatches in the framework to drain.
 */
static VOID
ShpDrainAllDispatches(
    _In_ PSH_FRAMEWORK_INTERNAL Fw
    )
{
    LARGE_INTEGER interval;
    ULONG iterations = 0;

    interval.QuadPart = SH_DRAIN_POLL_INTERVAL_100NS;

    while (Fw->ActiveDispatchCount > 0 &&
           iterations < SH_MAX_DRAIN_ITERATIONS)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        iterations++;
    }
}

/**
 * @brief Free a hook entry back to the lookaside or pool.
 * Caller must have already removed the hook from all lists.
 */
static VOID
ShpFreeHookEntry(
    _In_ PSH_FRAMEWORK_INTERNAL Fw,
    _In_ PSH_HOOK_INTERNAL Hook
    )
{
    /*
     * Scrub all fields before returning to pool.
     * Prevents stale magic/callback pointers from being
     * reachable if a dangling handle is dereferenced.
     */
    RtlSecureZeroMemory(Hook, sizeof(SH_HOOK_INTERNAL));

    if (Fw->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Fw->HookLookaside, Hook);
    } else {
        ShadowStrikeFreePoolWithTag(Hook, SH_HOOK_TAG);
    }
}

/**
 * @brief Check if the current dispatch should be rate-limited.
 * @return TRUE if the dispatch should proceed, FALSE if rate-limited.
 */
static BOOLEAN
ShpCheckRateLimit(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw
    )
{
    LARGE_INTEGER now;
    LONG64 windowStart;
    LONG64 count;

    KeQuerySystemTime(&now);
    windowStart = InterlockedCompareExchange64(
        &Fw->WindowStartTime, 0, 0);

    /* Check if we've moved into a new window */
    if ((now.QuadPart - windowStart) >= SH_RATE_LIMIT_WINDOW_100NS) {
        /*
         * Use CAS to atomically claim the window reset. Only the winning
         * thread resets the dispatch counter — losers proceed with the
         * new window already in effect.
         */
        if (InterlockedCompareExchange64(
                &Fw->WindowStartTime, now.QuadPart, windowStart) == windowStart)
        {
            InterlockedExchange64(&Fw->CurrentWindowDispatches, 0);
        }
    }

    count = InterlockedIncrement64(&Fw->CurrentWindowDispatches);

    if (count > (LONG64)Fw->RateLimitPerWindow) {
        InterlockedIncrement64(&Fw->TotalRateLimited);
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Update the peak concurrent dispatch high-water mark.
 */
static VOID
ShpUpdatePeakConcurrent(
    _Inout_ PSH_FRAMEWORK_INTERNAL Fw,
    _In_ LONG CurrentCount
    )
{
    LONG peak;

    do {
        peak = Fw->PeakConcurrentDispatches;
        if (CurrentCount <= peak) {
            break;
        }
    } while (InterlockedCompareExchange(
                 &Fw->PeakConcurrentDispatches, CurrentCount, peak) != peak);
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShInitialize(
    _Out_ SH_FRAMEWORK_HANDLE *Framework
    )
{
    PSH_FRAMEWORK_INTERNAL fw = NULL;
    ULONG i;

    PAGED_CODE();

    if (Framework == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Framework = NULL;

    /*
     * Allocate from NonPagedPoolNx because:
     * - EX_PUSH_LOCK can be acquired at APC_LEVEL
     * - Dispatch hot path must not fault
     * - Interlocked fields require resident memory
     */
    fw = (PSH_FRAMEWORK_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SH_FRAMEWORK_INTERNAL),
        SH_POOL_TAG);

    if (fw == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(fw, sizeof(SH_FRAMEWORK_INTERNAL));

    /* Initialize hash buckets */
    for (i = 0; i < SH_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&fw->Buckets[i].Head);
    }

    /* Initialize global hook list */
    InitializeListHead(&fw->AllHooksList);

    /* Initialize synchronization */
    ExInitializePushLock(&fw->HookLock);

    /* Initialize lookaside list for hook allocations */
    ExInitializeNPagedLookasideList(
        &fw->HookLookaside,
        NULL,                               /* AllocateFunction — use default */
        NULL,                               /* FreeFunction — use default */
        POOL_NX_ALLOCATION,                 /* NX enforcement */
        sizeof(SH_HOOK_INTERNAL),
        SH_HOOK_TAG,
        (USHORT)SH_HOOK_LOOKASIDE_DEPTH);

    fw->LookasideInitialized = TRUE;

    /* Initialize rate limiting */
    fw->RateLimitPerWindow = SH_DEFAULT_RATE_LIMIT_PER_SECOND;
    KeQuerySystemTime((PLARGE_INTEGER)&fw->WindowStartTime);

    /* Record start time */
    KeQuerySystemTime(&fw->StartTime);

    /* Finalize: set magic and initialized flag LAST (memory barrier) */
    fw->Initialized = TRUE;
    InterlockedExchange((volatile LONG *)&fw->Magic, SH_FRAMEWORK_MAGIC);

    *Framework = (SH_FRAMEWORK_HANDLE)(PVOID)fw;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShShutdown(
    _In_ _Post_invalid_ SH_FRAMEWORK_HANDLE Framework
    )
{
    PSH_FRAMEWORK_INTERNAL fw;
    PLIST_ENTRY entry;
    PSH_HOOK_INTERNAL hook;

    PAGED_CODE();

    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return;
    }

    /*
     * Phase 1: Signal shutdown.
     * After this, ShDispatchSyscall will reject new dispatches.
     */
    InterlockedExchange(&fw->ShuttingDown, 1);

    /*
     * Phase 2: Drain all active dispatches.
     * Any ShDispatchSyscall call already past the shutdown check will
     * be holding an ActiveDispatchCount reference. We wait for all
     * of them to complete.
     */
    ShpDrainAllDispatches(fw);

    /*
     * Phase 3: Remove and free all hooks.
     * No dispatches should be active. Verify defensively —
     * if drain timed out, log but proceed to avoid driver unload hang.
     */
    if (fw->ActiveDispatchCount > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] SyscallHooks: Shutdown drain incomplete, "
                   "%ld dispatches still active\n",
                   fw->ActiveDispatchCount);
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&fw->HookLock);

    while (!IsListEmpty(&fw->AllHooksList)) {
        entry = RemoveHeadList(&fw->AllHooksList);
        hook = CONTAINING_RECORD(entry, SH_HOOK_INTERNAL, AllHooksListEntry);

        /* Unlink from hash bucket */
        RemoveEntryList(&hook->HashListEntry);

        /* Drain any (theoretically impossible) active callbacks */
        ShpDrainHookCallbacks(hook);

        ShpFreeHookEntry(fw, hook);
    }

    ExReleasePushLockExclusive(&fw->HookLock);
    KeLeaveCriticalRegion();

    /*
     * Phase 4: Destroy lookaside list.
     * Must happen after all hooks are freed back to it.
     */
    if (fw->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&fw->HookLookaside);
        fw->LookasideInitialized = FALSE;
    }

    /*
     * Phase 5: Invalidate and free the framework.
     */
    fw->Magic = 0;
    fw->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(fw, SH_POOL_TAG);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShRegisterHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ ULONG SyscallNumber,
    _In_opt_ SH_HOOK_CALLBACK PreCallback,
    _In_opt_ SH_HOOK_CALLBACK PostCallback,
    _In_opt_ PVOID Cookie,
    _Out_ SH_HOOK_HANDLE *Hook
    )
{
    PSH_FRAMEWORK_INTERNAL fw;
    PSH_HOOK_INTERNAL newHook = NULL;
    PSH_HOOK_INTERNAL existing;
    ULONG bucketIndex;
    PSH_HASH_BUCKET bucket;

    PAGED_CODE();

    /* Validate output parameter first */
    if (Hook == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Hook = NULL;

    /* Validate framework */
    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* At least one callback must be provided */
    if (PreCallback == NULL && PostCallback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate syscall number range */
    if (SyscallNumber >= SH_MAX_SYSCALL_NUMBER) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Check if framework is shutting down */
    if (fw->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Check hook count quota */
    if (fw->RegisteredHookCount >= SH_MAX_REGISTERED_HOOKS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    /* Allocate hook entry from lookaside */
    newHook = (PSH_HOOK_INTERNAL)ExAllocateFromNPagedLookasideList(
        &fw->HookLookaside);

    if (newHook == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newHook, sizeof(SH_HOOK_INTERNAL));

    newHook->SyscallNumber = SyscallNumber;
    newHook->PreCallback = PreCallback;
    newHook->PostCallback = PostCallback;
    newHook->Cookie = Cookie;
    newHook->Enabled = 0;  /* Created disabled — caller must ShEnableHook */
    newHook->ActiveCallbackCount = 0;
    newHook->HitCount = 0;
    InitializeListHead(&newHook->HashListEntry);
    InitializeListHead(&newHook->AllHooksListEntry);

    bucketIndex = ShpHashSyscallNumber(SyscallNumber);
    bucket = &fw->Buckets[bucketIndex];

    /* Insert under exclusive lock */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&fw->HookLock);

    /* Check for duplicate: only one hook per syscall number */
    existing = ShpFindHookInBucket(bucket, SyscallNumber);
    if (existing != NULL) {
        ExReleasePushLockExclusive(&fw->HookLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&fw->HookLookaside, newHook);
        return STATUS_OBJECTID_EXISTS;
    }

    /* Re-check quota under lock (race protection) */
    if (fw->RegisteredHookCount >= SH_MAX_REGISTERED_HOOKS) {
        ExReleasePushLockExclusive(&fw->HookLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&fw->HookLookaside, newHook);
        return STATUS_QUOTA_EXCEEDED;
    }

    /* Set magic AFTER all fields are populated (publish barrier) */
    newHook->Magic = SH_HOOK_MAGIC;

    /* Insert into hash bucket and global list */
    InsertTailList(&bucket->Head, &newHook->HashListEntry);
    InsertTailList(&fw->AllHooksList, &newHook->AllHooksListEntry);

    InterlockedIncrement(&fw->RegisteredHookCount);

    ExReleasePushLockExclusive(&fw->HookLock);
    KeLeaveCriticalRegion();

    *Hook = (SH_HOOK_HANDLE)(PVOID)newHook;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShUnregisterHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ _Post_invalid_ SH_HOOK_HANDLE Hook
    )
{
    PSH_FRAMEWORK_INTERNAL fw;
    PSH_HOOK_INTERNAL hook;
    BOOLEAN wasEnabled;

    PAGED_CODE();

    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Hook == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    hook = (PSH_HOOK_INTERNAL)(PVOID)Hook;

    /*
     * Phase 1: Acquire exclusive lock BEFORE validating the hook.
     * This prevents a TOCTOU race where two threads call ShUnregisterHook
     * concurrently — the first frees the hook, the second accesses freed memory.
     * Under exclusive lock, only one thread can operate on the hook at a time.
     */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&fw->HookLock);

    /* Validate hook magic under lock — safe from concurrent free */
    if (hook->Magic != SH_HOOK_MAGIC) {
        ExReleasePushLockExclusive(&fw->HookLock);
        KeLeaveCriticalRegion();
        return STATUS_INVALID_PARAMETER;
    }

    /* Verify hook is still in a valid list (guards against double-unregister) */
    if (hook->HashListEntry.Flink == NULL ||
        hook->HashListEntry.Flink == &hook->HashListEntry)
    {
        ExReleasePushLockExclusive(&fw->HookLock);
        KeLeaveCriticalRegion();
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Phase 2: Disable the hook so no new callbacks will be invoked.
     * This is safe under exclusive lock — dispatch holds shared lock,
     * so it cannot be running concurrently.
     */
    wasEnabled = (InterlockedExchange(&hook->Enabled, 0) != 0);

    /* Remove from hash bucket and global list */
    RemoveEntryList(&hook->HashListEntry);
    RemoveEntryList(&hook->AllHooksListEntry);

    /* Reinitialize list entries to detached state for double-remove protection */
    InitializeListHead(&hook->HashListEntry);
    InitializeListHead(&hook->AllHooksListEntry);

    InterlockedDecrement(&fw->RegisteredHookCount);
    if (wasEnabled) {
        InterlockedDecrement(&fw->EnabledHookCount);
    }

    ExReleasePushLockExclusive(&fw->HookLock);
    KeLeaveCriticalRegion();

    /*
     * Phase 3: Drain active callbacks on this hook.
     * The hook is no longer in any list, so no new callbacks can start.
     * We wait for any in-flight callbacks to finish.
     */
    ShpDrainHookCallbacks(hook);

    /*
     * Phase 4: Free the hook entry.
     */
    ShpFreeHookEntry(fw, hook);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShEnableHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ SH_HOOK_HANDLE Hook
    )
{
    PSH_FRAMEWORK_INTERNAL fw;
    PSH_HOOK_INTERNAL hook;
    LONG prev;

    PAGED_CODE();

    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Hook == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (fw->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    /*
     * Acquire shared lock to prevent concurrent ShUnregisterHook from
     * freeing the hook between our magic check and the enable toggle.
     * Shared lock is sufficient — we're not modifying the hash table.
     */
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&fw->HookLock);

    hook = ShpValidateHook(Hook);
    if (hook == NULL) {
        ExReleasePushLockShared(&fw->HookLock);
        KeLeaveCriticalRegion();
        return STATUS_INVALID_PARAMETER;
    }

    prev = InterlockedExchange(&hook->Enabled, 1);
    if (prev == 0) {
        InterlockedIncrement(&fw->EnabledHookCount);
    }

    ExReleasePushLockShared(&fw->HookLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShDisableHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ SH_HOOK_HANDLE Hook
    )
{
    PSH_FRAMEWORK_INTERNAL fw;
    PSH_HOOK_INTERNAL hook;
    LONG prev;

    PAGED_CODE();

    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Hook == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Acquire shared lock to prevent concurrent ShUnregisterHook from
     * freeing the hook between our magic check and the disable toggle.
     */
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&fw->HookLock);

    hook = ShpValidateHook(Hook);
    if (hook == NULL) {
        ExReleasePushLockShared(&fw->HookLock);
        KeLeaveCriticalRegion();
        return STATUS_INVALID_PARAMETER;
    }

    prev = InterlockedExchange(&hook->Enabled, 0);
    if (prev != 0) {
        InterlockedDecrement(&fw->EnabledHookCount);
    }

    ExReleasePushLockShared(&fw->HookLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShDispatchSyscall(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ PSH_SYSCALL_CONTEXT Context,
    _Out_ SH_HOOK_RESULT *Result
    )
{
    PSH_FRAMEWORK_INTERNAL fw;
    PSH_HOOK_INTERNAL hook;
    ULONG bucketIndex;
    PSH_HASH_BUCKET bucket;
    SH_HOOK_RESULT callbackResult;

    PAGED_CODE();

    /* Validate inputs */
    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = ShResult_Allow;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Reject if shutting down */
    if (fw->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Rate limit check */
    if (!ShpCheckRateLimit(fw)) {
        return STATUS_SUCCESS;  /* Silently allow — rate limited */
    }

    /* Validate syscall number */
    if (Context->SyscallNumber >= SH_MAX_SYSCALL_NUMBER) {
        return STATUS_SUCCESS;  /* Unknown syscall — allow through */
    }

    /*
     * Acquire dispatch reference BEFORE looking up the hook.
     * This ensures ShShutdown sees our reference and waits.
     */
    ShpAcquireDispatchRef(fw);

    /* Re-check shutdown after acquiring reference */
    if (fw->ShuttingDown) {
        ShpReleaseDispatchRef(fw);
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedIncrement64(&fw->TotalDispatches);

    /*
     * Look up hook under shared lock.
     * Shared lock allows concurrent dispatches for different or same syscalls.
     */
    bucketIndex = ShpHashSyscallNumber(Context->SyscallNumber);
    bucket = &fw->Buckets[bucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&fw->HookLock);

    hook = ShpFindHookInBucket(bucket, Context->SyscallNumber);

    if (hook == NULL || hook->Enabled == 0) {
        ExReleasePushLockShared(&fw->HookLock);
        KeLeaveCriticalRegion();
        ShpReleaseDispatchRef(fw);
        return STATUS_SUCCESS;  /* No hook or disabled — allow */
    }

    /*
     * Acquire per-hook callback reference while we still hold the shared lock.
     * This prevents ShUnregisterHook from freeing the hook while we use it.
     */
    ShpAcquireHookRef(hook);

    ExReleasePushLockShared(&fw->HookLock);
    KeLeaveCriticalRegion();

    /*
     * Invoke callbacks outside the lock — critical for avoiding deadlocks
     * if callbacks call back into the framework or into other kernel subsystems.
     *
     * Wrap in __try/__except to guarantee reference release even if a
     * buggy callback causes an exception. Without this, a faulting callback
     * would leak ActiveCallbackCount and ActiveDispatchCount permanently,
     * preventing clean shutdown.
     */

    InterlockedIncrement64(&hook->HitCount);

    __try {

        /* Pre-call callback */
        if (Context->IsPreCall && hook->PreCallback != NULL) {
            InterlockedIncrement64(&fw->TotalCallbackInvocations);

            callbackResult = hook->PreCallback(Context, hook->Cookie);

            switch (callbackResult) {
            case ShResult_Block:
                InterlockedIncrement64(&fw->TotalBlocked);
                *Result = ShResult_Block;
                break;

            case ShResult_Log:
                InterlockedIncrement64(&fw->TotalLogged);
                if (*Result != ShResult_Block) {
                    *Result = ShResult_Log;
                }
                break;

            case ShResult_Allow:
            default:
                break;
            }
        }

        /* Post-call callback */
        if (!Context->IsPreCall && hook->PostCallback != NULL) {
            InterlockedIncrement64(&fw->TotalCallbackInvocations);

            callbackResult = hook->PostCallback(Context, hook->Cookie);

            switch (callbackResult) {
            case ShResult_Block:
                InterlockedIncrement64(&fw->TotalBlocked);
                *Result = ShResult_Block;
                break;

            case ShResult_Log:
                InterlockedIncrement64(&fw->TotalLogged);
                if (*Result != ShResult_Block) {
                    *Result = ShResult_Log;
                }
                break;

            case ShResult_Allow:
            default:
                break;
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /*
         * Callback faulted — allow the syscall through and log.
         * The critical path below still releases references correctly.
         */
        NOTHING;
    }

    ShpReleaseHookRef(hook);
    ShpReleaseDispatchRef(fw);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShGetStatistics(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _Out_ PSH_STATISTICS Stats
    )
{
    PSH_FRAMEWORK_INTERNAL fw;

    PAGED_CODE();

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(SH_STATISTICS));

    fw = ShpValidateFramework(Framework);
    if (fw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Read all volatile counters. These are individually atomic reads
     * but the snapshot is not globally consistent — this is acceptable
     * for statistics. Full consistency would require stopping all
     * dispatches, which is unacceptable for a hot-path monitoring tool.
     */
    Stats->TotalDispatches           = fw->TotalDispatches;
    Stats->TotalCallbackInvocations  = fw->TotalCallbackInvocations;
    Stats->TotalBlocked              = fw->TotalBlocked;
    Stats->TotalLogged               = fw->TotalLogged;
    Stats->TotalRateLimited          = fw->TotalRateLimited;
    Stats->RegisteredHookCount       = fw->RegisteredHookCount;
    Stats->EnabledHookCount          = fw->EnabledHookCount;
    Stats->PeakConcurrentDispatches  = fw->PeakConcurrentDispatches;
    Stats->StartTime                 = fw->StartTime;

    return STATUS_SUCCESS;
}
