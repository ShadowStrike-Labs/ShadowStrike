/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE LOOKASIDE LIST MANAGER
 * ============================================================================
 *
 * @file LookasideLists.h
 * @brief High-performance lookaside list management for kernel-mode EDR.
 *
 * Provides enterprise-grade lookaside list infrastructure with:
 * - Centralized management of all driver lookaside lists
 * - Comprehensive hit/miss statistics for tuning
 * - Memory pressure awareness and adaptive behavior
 * - Per-list and global memory accounting
 * - Automatic cleanup and leak detection
 *
 * Performance Characteristics:
 * - O(1) allocation and deallocation from hot path
 * - Lock-free statistics updates via interlocked operations
 *
 * Security Guarantees:
 * - All allocated blocks are zeroed (prevents information leaks)
 * - Magic value validation to detect corruption
 * - Poison patterns on free for use-after-free detection
 * - Bounds checking on all operations
 * - EX_RUNDOWN_REF prevents use-after-free on shutdown
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_LOOKASIDE_LISTS_H_
#define _SHADOWSTRIKE_LOOKASIDE_LISTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define LL_POOL_TAG                     'SSLL'
#define LL_ENTRY_TAG                    'ELSS'
#define LL_META_TAG                     'MLSS'
#define LL_WORKITEM_TAG                 'WLSS'

// ============================================================================
// CONSTANTS
// ============================================================================

#define LL_MAX_NAME_LENGTH              32
#define LL_MAX_LOOKASIDE_LISTS          256
#define LL_DEFAULT_DEPTH                256
#define LL_MIN_DEPTH                    16
#define LL_MAX_DEPTH                    4096
#define LL_MIN_ENTRY_SIZE               sizeof(PVOID)
#define LL_MAX_ENTRY_SIZE               (64 * 1024)
#define LL_STATS_SAMPLE_INTERVAL_MS     1000
#define LL_MEMORY_PRESSURE_HIGH         80
#define LL_MEMORY_PRESSURE_LOW          60
#define LL_ENTRY_MAGIC                  0x4C4C5353
#define LL_MANAGER_MAGIC                0x4D4C5353
#define LL_POISON_PATTERN               0xDE
#define LL_CACHE_LINE_SIZE              64
#define LL_REFCOUNT_DRAIN_MAX_ITERATIONS    100
#define LL_REFCOUNT_DRAIN_INTERVAL_MS       10

/**
 * @brief Destroying flag in bit 63 of the combined RefCountAndState word
 */
#define LL_DESTROYING_FLAG              0x8000000000000000ULL

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _LL_STATE {
    LlStateUninitialized = 0,
    LlStateInitializing,
    LlStateActive,
    LlStateSuspended,
    LlStateDestroying,
    LlStateDestroyed
} LL_STATE;

typedef enum _LL_ALLOC_FLAGS {
    LlAllocNone             = 0x00000000,
    LlAllocZeroMemory       = 0x00000001,
    LlAllocMustSucceed      = 0x00000002,
    LlAllocPreferCache      = 0x00000004,
    LlAllocHighPriority     = 0x00000008,
    LlAllocSecure           = 0x00000010
} LL_ALLOC_FLAGS;

typedef enum _LL_MEMORY_PRESSURE {
    LlPressureNone = 0,
    LlPressureModerate,
    LlPressureHigh,
    LlPressureCritical
} LL_MEMORY_PRESSURE;

// ============================================================================
// STATISTICS STRUCTURES
// ============================================================================

typedef struct DECLSPEC_CACHEALIGN _LL_STATISTICS {
    volatile LONG64 TotalAllocations;
    volatile LONG64 TotalFrees;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG CurrentOutstanding;
    volatile LONG PeakOutstanding;
    volatile LONG64 AllocationFailures;
    volatile LONG64 TotalBytesAllocated;
    volatile LONG64 TotalBytesFreed;
    volatile LONG64 AverageLatency;
    volatile LONG64 MaxLatency;
    volatile LONG64 SecureFrees;
} LL_STATISTICS, *PLL_STATISTICS;

typedef struct _LL_GLOBAL_STATISTICS {
    volatile LONG64 TotalAllocations;
    volatile LONG64 TotalFrees;
    volatile LONG64 TotalCacheHits;
    volatile LONG64 TotalCacheMisses;
    volatile LONG64 CurrentMemoryUsage;
    volatile LONG64 PeakMemoryUsage;
    volatile LONG ActiveLookasideLists;
    volatile LONG64 MemoryPressureEvents;
    volatile LONG64 RefCountRaces;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastResetTime;
} LL_GLOBAL_STATISTICS, *PLL_GLOBAL_STATISTICS;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

struct _LL_MANAGER;

// ============================================================================
// LOOKASIDE LIST STRUCTURE
// ============================================================================

/**
 * @brief Individual lookaside list descriptor
 *
 * Lock-free reference counting via combined 64-bit word:
 * - Bits 0-30:  Reference count (0 to 0x7FFFFFFF)
 * - Bit 31:     Reserved
 * - Bits 32-62: Sequence counter (ABA protection)
 * - Bit 63:     Destroying flag
 */
typedef struct _LL_LOOKASIDE {
    LIST_ENTRY ListEntry;
    CHAR Name[LL_MAX_NAME_LENGTH];
    ULONG Id;
    ULONG Tag;
    SIZE_T EntrySize;
    SIZE_T AlignedSize;
    POOL_TYPE PoolType;
    BOOLEAN IsPaged;
    volatile LL_STATE State;
    ULONG Flags;

    union {
        NPAGED_LOOKASIDE_LIST NonPaged;
        PAGED_LOOKASIDE_LIST Paged;
    } NativeList;

    LL_STATISTICS Stats;
    LARGE_INTEGER CreateTime;

    /// Atomic last access time (prevents torn writes)
    volatile LONGLONG LastAccessTime;

    ULONG Magic;

    volatile LONG64 RefCountAndState;

    struct _LL_MANAGER* Manager;

} LL_LOOKASIDE, *PLL_LOOKASIDE;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

typedef VOID (*LL_PRESSURE_CALLBACK)(
    _In_ LL_MEMORY_PRESSURE PressureLevel,
    _In_ LONG64 CurrentMemory,
    _In_ LONG64 MemoryLimit,
    _In_opt_ PVOID Context
);

typedef BOOLEAN (*LL_ENUM_CALLBACK)(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_opt_ PVOID Context
);

// ============================================================================
// MANAGER STRUCTURE
// ============================================================================

/**
 * @brief Central lookaside list manager
 *
 * Uses EX_RUNDOWN_REF for safe shutdown — all public APIs acquire
 * rundown protection; shutdown waits for all ops to complete.
 */
typedef struct _LL_MANAGER {
    ULONG Magic;
    volatile LL_STATE State;

    /// Rundown protection for safe shutdown (replaces BOOLEAN Initialized)
    EX_RUNDOWN_REF RundownRef;

    LIST_ENTRY LookasideListHead;
    EX_PUSH_LOCK LookasideListLock;

    volatile LONG LookasideCount;
    volatile LONG NextLookasideId;

    LL_GLOBAL_STATISTICS GlobalStats;

    LONG64 MemoryLimit;
    LL_MEMORY_PRESSURE PressureLevel;

    /// Pressure callback (written atomically via InterlockedExchangePointer)
    LL_PRESSURE_CALLBACK PressureCallback;
    PVOID PressureCallbackContext;

    KTIMER MaintenanceTimer;
    KDPC MaintenanceDpc;
    ULONG MaintenanceIntervalMs;
    BOOLEAN MaintenanceEnabled;

    /// Work item for deferred pressure callback
    PIO_WORKITEM PressureWorkItem;
    PDEVICE_OBJECT DeviceObject;

    volatile LL_MEMORY_PRESSURE PendingPressureLevel;
    volatile LONG64 PendingCurrentMemory;
    volatile LONG64 PendingMemoryLimit;
    volatile LONG PressureWorkPending;

    BOOLEAN SelfTuningEnabled;
    BOOLEAN DebugMode;

} LL_MANAGER, *PLL_MANAGER;

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the lookaside list manager.
 *
 * @param Manager       Receives pointer to initialized manager
 * @param DeviceObject  Device object for work item operations
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 *
 * @note NOT placed in INIT segment — safe to call after DriverEntry.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlInitialize(
    _Out_ PLL_MANAGER* Manager,
    _In_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @brief Shutdown the lookaside list manager.
 *
 * Destroys all managed lookaside lists, waits for rundown,
 * and releases all resources. Sets *pManager to NULL on return.
 *
 * @param pManager  Pointer to manager pointer (set to NULL on return)
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlShutdown(
    _Inout_ PLL_MANAGER* pManager
    );

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
    );

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
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlDestroyLookaside(
    _In_ PLL_MANAGER Manager,
    _In_ PLL_LOOKASIDE Lookaside
    );

// ============================================================================
// REFERENCE COUNTING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LlReferenceLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlReleaseLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    );

// ============================================================================
// ALLOCATION AND DEALLOCATION
// ============================================================================

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
PVOID
LlAllocate(
    _In_ PLL_LOOKASIDE Lookaside
    );

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
PVOID
LlAllocateEx(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ ULONG Flags
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlSecureFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    );

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetStatistics(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PLL_STATISTICS Statistics
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetHitMissRatio(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PULONG64 Hits,
    _Out_ PULONG64 Misses
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetGlobalStatistics(
    _In_ PLL_MANAGER Manager,
    _Out_ PLL_GLOBAL_STATISTICS Statistics
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlResetStatistics(
    _In_ PLL_LOOKASIDE Lookaside
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlResetGlobalStatistics(
    _In_ PLL_MANAGER Manager
    );

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlSetMemoryLimit(
    _In_ PLL_MANAGER Manager,
    _In_ LONG64 MemoryLimit
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG64
LlGetMemoryUsage(
    _In_ PLL_MANAGER Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlRegisterPressureCallback(
    _In_ PLL_MANAGER Manager,
    _In_ LL_PRESSURE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
LONG64
LlTrimCaches(
    _In_ PLL_MANAGER Manager
    );

// ============================================================================
// MAINTENANCE AND TUNING
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlEnableMaintenance(
    _In_ PLL_MANAGER Manager,
    _In_ ULONG IntervalMs
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlDisableMaintenance(
    _In_ PLL_MANAGER Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlEnableSelfTuning(
    _In_ PLL_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

// ============================================================================
// ENUMERATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlEnumerateLookasides(
    _In_ PLL_MANAGER Manager,
    _In_ LL_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlFindByName(
    _In_ PLL_MANAGER Manager,
    _In_ PCSTR Name,
    _Out_ PLL_LOOKASIDE* Lookaside
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlFindByTag(
    _In_ PLL_MANAGER Manager,
    _In_ ULONG Tag,
    _Out_ PLL_LOOKASIDE* Lookaside
    );

// ============================================================================
// DEBUG AND DIAGNOSTICS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlSetDebugMode(
    _In_ PLL_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LlValidateLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlDumpDiagnostics(
    _In_ PLL_MANAGER Manager
    );

// ============================================================================
// LEGACY COMPATIBILITY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetStats(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PULONG64 Hits,
    _Out_ PULONG64 Misses
    );

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

FORCEINLINE
ULONG
LlCalculateHitRate(
    _In_ LONG64 Hits,
    _In_ LONG64 Misses
    )
{
    LONG64 Total = Hits + Misses;
    if (Total <= 0) {
        return 0;
    }
    return (ULONG)(((ULONG64)Hits * 100ULL) / (ULONG64)Total);
}

FORCEINLINE
BOOLEAN
LlIsValid(
    _In_opt_ PLL_LOOKASIDE Lookaside
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
    return TRUE;
}

FORCEINLINE
BOOLEAN
LlManagerIsValid(
    _In_opt_ PLL_MANAGER Manager
    )
{
    if (Manager == NULL) {
        return FALSE;
    }
    if (Manager->Magic != LL_MANAGER_MAGIC) {
        return FALSE;
    }
    if ((LL_STATE)InterlockedCompareExchange(
            (volatile LONG*)&Manager->State, 0, 0) != LlStateActive) {
        return FALSE;
    }
    return TRUE;
}

FORCEINLINE
BOOLEAN
LlSafeAdd(
    _In_ SIZE_T Size1,
    _In_ SIZE_T Size2,
    _Out_ PSIZE_T Result
    )
{
    if (Size1 > (SIZE_T)(-1) - Size2) {
        *Result = 0;
        return FALSE;
    }
    *Result = Size1 + Size2;
    return TRUE;
}

FORCEINLINE
BOOLEAN
LlSafeMultiply(
    _In_ SIZE_T Size1,
    _In_ SIZE_T Size2,
    _Out_ PSIZE_T Result
    )
{
    if (Size2 != 0 && Size1 > (SIZE_T)(-1) / Size2) {
        *Result = 0;
        return FALSE;
    }
    *Result = Size1 * Size2;
    return TRUE;
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_LOOKASIDE_LISTS_H_
