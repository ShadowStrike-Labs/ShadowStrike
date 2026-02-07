/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE LOOKASIDE LIST MANAGER
 * ============================================================================
 *
 * @file LookasideLists.h
 * @brief High-performance lookaside list management for kernel-mode EDR.
 *
 * Provides CrowdStrike Falcon-class lookaside list infrastructure with:
 * - Centralized management of all driver lookaside lists
 * - Automatic sizing based on allocation patterns
 * - Comprehensive hit/miss statistics for tuning
 * - Memory pressure awareness and adaptive behavior
 * - Per-list and global memory accounting
 * - NUMA-aware allocation for multi-socket systems
 * - Automatic cleanup and leak detection
 * - Integration with performance monitoring subsystem
 *
 * Performance Characteristics:
 * - O(1) allocation and deallocation from hot path
 * - Lock-free statistics updates via interlocked operations
 * - Cache-line aligned structures to prevent false sharing
 * - Minimal memory fragmentation through fixed-size blocks
 *
 * Security Guarantees:
 * - All allocated blocks are zeroed (prevents information leaks)
 * - Magic value validation to detect corruption
 * - Poison patterns on free for use-after-free detection
 * - Bounds checking on all operations
 * - Reference counting prevents use-after-free
 *
 * Security Hardening (v3.0.0):
 * ============================
 * - Lock-free reference counting with atomic CAS operations
 * - Proper callback IRQL validation
 * - Safe list enumeration with next-pointer caching
 * - Work item deferral for DISPATCH_LEVEL callbacks
 * - State machine with atomic transitions
 * - ExAllocatePool2 usage for modern Windows
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (secure allocation tracking)
 * - T1003: Credential Dumping (memory zeroing)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Security Hardened)
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

/**
 * @brief Pool tag for lookaside manager: 'LLSS' (little-endian)
 */
#define LL_POOL_TAG                     'SSLL'

/**
 * @brief Pool tag for lookaside entries
 */
#define LL_ENTRY_TAG                    'ELSS'

/**
 * @brief Pool tag for lookaside metadata
 */
#define LL_META_TAG                     'MLSS'

/**
 * @brief Pool tag for work item context
 */
#define LL_WORKITEM_TAG                 'WLSS'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum lookaside name length
 */
#define LL_MAX_NAME_LENGTH              32

/**
 * @brief Maximum number of lookaside lists per manager
 */
#define LL_MAX_LOOKASIDE_LISTS          256

/**
 * @brief Default lookaside depth
 */
#define LL_DEFAULT_DEPTH                256

/**
 * @brief Minimum lookaside depth
 */
#define LL_MIN_DEPTH                    16

/**
 * @brief Maximum lookaside depth
 */
#define LL_MAX_DEPTH                    4096

/**
 * @brief Minimum entry size for lookaside
 */
#define LL_MIN_ENTRY_SIZE               sizeof(PVOID)

/**
 * @brief Maximum entry size for lookaside (64KB)
 */
#define LL_MAX_ENTRY_SIZE               (64 * 1024)

/**
 * @brief Statistics sampling interval (milliseconds)
 */
#define LL_STATS_SAMPLE_INTERVAL_MS     1000

/**
 * @brief High water mark for memory pressure detection (80%)
 */
#define LL_MEMORY_PRESSURE_HIGH         80

/**
 * @brief Low water mark for memory pressure recovery (60%)
 */
#define LL_MEMORY_PRESSURE_LOW          60

/**
 * @brief Magic value for entry validation
 */
#define LL_ENTRY_MAGIC                  0x4C4C5353  // 'SSLL'

/**
 * @brief Magic value for manager validation
 */
#define LL_MANAGER_MAGIC                0x4D4C5353  // 'SSLM'

/**
 * @brief Poison pattern for freed entries (debug)
 */
#define LL_POISON_PATTERN               0xDE

/**
 * @brief Cache line size for alignment
 */
#define LL_CACHE_LINE_SIZE              64

/**
 * @brief Reference count sentinel value (being destroyed)
 */
#define LL_REFCOUNT_DESTROYING          (-1)

/**
 * @brief Maximum wait iterations for reference drain
 */
#define LL_REFCOUNT_DRAIN_MAX_ITERATIONS    100

/**
 * @brief Drain interval in milliseconds
 */
#define LL_REFCOUNT_DRAIN_INTERVAL_MS       10

/**
 * @brief Sequence number increment for lock-free operations
 *
 * Used to detect ABA problems in lock-free reference counting.
 * The sequence counter occupies the upper 32 bits of a 64-bit word.
 */
#define LL_SEQUENCE_INCREMENT           0x100000000ULL

/**
 * @brief Mask to extract reference count from combined value
 */
#define LL_REFCOUNT_MASK                0x00000000FFFFFFFFULL

/**
 * @brief Flag indicating lookaside is being destroyed (in upper bits)
 */
#define LL_DESTROYING_FLAG              0x8000000000000000ULL

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Lookaside list state
 */
typedef enum _LL_STATE {
    /// Not initialized
    LlStateUninitialized = 0,

    /// Initializing
    LlStateInitializing,

    /// Initialized and ready
    LlStateActive,

    /// Temporarily suspended (memory pressure)
    LlStateSuspended,

    /// Being destroyed
    LlStateDestroying,

    /// Destroyed
    LlStateDestroyed

} LL_STATE;

/**
 * @brief Lookaside allocation flags
 */
typedef enum _LL_ALLOC_FLAGS {
    /// No special flags
    LlAllocNone             = 0x00000000,

    /// Zero memory on allocation (default)
    LlAllocZeroMemory       = 0x00000001,

    /// Must succeed - block until memory available
    LlAllocMustSucceed      = 0x00000002,

    /// Prefer cache allocation over pool
    LlAllocPreferCache      = 0x00000004,

    /// High priority allocation
    LlAllocHighPriority     = 0x00000008,

    /// Security sensitive - wipe on free
    LlAllocSecure           = 0x00000010

} LL_ALLOC_FLAGS;

/**
 * @brief Memory pressure level
 */
typedef enum _LL_MEMORY_PRESSURE {
    /// Normal operation
    LlPressureNone = 0,

    /// Moderate pressure - reduce caching
    LlPressureModerate,

    /// High pressure - minimal caching
    LlPressureHigh,

    /// Critical - emergency mode
    LlPressureCritical

} LL_MEMORY_PRESSURE;

// ============================================================================
// STATISTICS STRUCTURES
// ============================================================================

/**
 * @brief Per-lookaside statistics (cache-line aligned)
 */
typedef struct DECLSPEC_CACHEALIGN _LL_STATISTICS {
    /// Total allocations from this list
    volatile LONG64 TotalAllocations;

    /// Total frees to this list
    volatile LONG64 TotalFrees;

    /// Cache hits (allocation from lookaside)
    volatile LONG64 CacheHits;

    /// Cache misses (allocation from pool)
    volatile LONG64 CacheMisses;

    /// Current outstanding allocations
    volatile LONG CurrentOutstanding;

    /// Peak outstanding allocations
    volatile LONG PeakOutstanding;

    /// Allocation failures
    volatile LONG64 AllocationFailures;

    /// Total bytes allocated
    volatile LONG64 TotalBytesAllocated;

    /// Total bytes freed
    volatile LONG64 TotalBytesFreed;

    /// Average allocation latency (100ns units)
    volatile LONG64 AverageLatency;

    /// Maximum allocation latency
    volatile LONG64 MaxLatency;

    /// Secure frees count
    volatile LONG64 SecureFrees;

    /// Padding for cache line alignment
    UCHAR Reserved[LL_CACHE_LINE_SIZE -
                   (sizeof(LONG64) * 10 + sizeof(LONG) * 2) % LL_CACHE_LINE_SIZE];

} LL_STATISTICS, *PLL_STATISTICS;

/**
 * @brief Global manager statistics
 */
typedef struct _LL_GLOBAL_STATISTICS {
    /// Total allocations across all lists
    volatile LONG64 TotalAllocations;

    /// Total frees across all lists
    volatile LONG64 TotalFrees;

    /// Total cache hits
    volatile LONG64 TotalCacheHits;

    /// Total cache misses
    volatile LONG64 TotalCacheMisses;

    /// Current total memory usage
    volatile LONG64 CurrentMemoryUsage;

    /// Peak memory usage
    volatile LONG64 PeakMemoryUsage;

    /// Number of active lookaside lists
    volatile LONG ActiveLookasideLists;

    /// Memory pressure events
    volatile LONG64 MemoryPressureEvents;

    /// Reference count races detected
    volatile LONG64 RefCountRaces;

    /// Manager start time
    LARGE_INTEGER StartTime;

    /// Last statistics reset time
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
 */
typedef struct _LL_LOOKASIDE {
    /// List entry for manager tracking
    LIST_ENTRY ListEntry;

    /// Human-readable name for debugging
    CHAR Name[LL_MAX_NAME_LENGTH];

    /// Unique identifier
    ULONG Id;

    /// Pool tag for allocations
    ULONG Tag;

    /// Size of each entry
    SIZE_T EntrySize;

    /// Aligned size (for internal use)
    SIZE_T AlignedSize;

    /// Pool type
    POOL_TYPE PoolType;

    /// Is paged pool
    BOOLEAN IsPaged;

    /// Current state (atomic)
    volatile LL_STATE State;

    /// Allocation flags
    ULONG Flags;

    /// Reserved for alignment
    UCHAR Reserved1[2];

    /// Native lookaside list
    union {
        NPAGED_LOOKASIDE_LIST NonPaged;
        PAGED_LOOKASIDE_LIST Paged;
    } NativeList;

    /// Statistics
    LL_STATISTICS Stats;

    /// Creation time
    LARGE_INTEGER CreateTime;

    /// Last access time
    LARGE_INTEGER LastAccessTime;

    /// Magic value for validation
    ULONG Magic;

    /**
     * @brief Combined reference count and state word (lock-free)
     *
     * Layout (64-bit):
     * - Bits 0-30:  Reference count (0 to 0x7FFFFFFF)
     * - Bit 31:     Reserved
     * - Bits 32-62: Sequence counter (ABA protection)
     * - Bit 63:     Destroying flag (1 = being destroyed)
     *
     * This design eliminates the TOCTOU race between checking RemovedFromList
     * and incrementing ReferenceCount by combining both into a single atomic
     * 64-bit compare-and-swap operation.
     */
    volatile LONG64 RefCountAndState;

    /// Back pointer to manager
    struct _LL_MANAGER* Manager;

    /// Custom allocator (optional)
    PVOID (*CustomAllocate)(POOL_TYPE, SIZE_T, ULONG);

    /// Custom deallocator (optional)
    VOID (*CustomFree)(PVOID);

} LL_LOOKASIDE, *PLL_LOOKASIDE;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Callback for memory pressure notification
 *
 * @note MUST be in non-paged memory as it may be called at DISPATCH_LEVEL
 *       via deferred work item. If called from DPC context, actual execution
 *       is deferred to a work item at PASSIVE_LEVEL.
 */
typedef VOID (*LL_PRESSURE_CALLBACK)(
    _In_ LL_MEMORY_PRESSURE PressureLevel,
    _In_ LONG64 CurrentMemory,
    _In_ LONG64 MemoryLimit,
    _In_opt_ PVOID Context
);

/**
 * @brief Callback for lookaside enumeration
 */
typedef BOOLEAN (*LL_ENUM_CALLBACK)(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_opt_ PVOID Context
);

// ============================================================================
// MANAGER STRUCTURE
// ============================================================================

/**
 * @brief Central lookaside list manager
 */
typedef struct _LL_MANAGER {
    /// Manager initialized
    BOOLEAN Initialized;

    /// Manager state (atomic)
    volatile LL_STATE State;

    /// Reserved for alignment
    UCHAR Reserved1[2];

    /// Magic value for validation
    ULONG Magic;

    /// List of all managed lookaside lists
    LIST_ENTRY LookasideListHead;

    /// Lock for lookaside list management
    EX_PUSH_LOCK LookasideListLock;

    /// Number of active lookaside lists
    volatile LONG LookasideCount;

    /// Next lookaside ID
    volatile LONG NextLookasideId;

    /// Global statistics
    LL_GLOBAL_STATISTICS GlobalStats;

    /// Memory limit (0 = unlimited)
    LONG64 MemoryLimit;

    /// Current memory pressure level
    LL_MEMORY_PRESSURE PressureLevel;

    /// Pressure callback
    LL_PRESSURE_CALLBACK PressureCallback;
    PVOID PressureCallbackContext;

    /// TRUE if pressure callback is in non-paged memory (validated)
    BOOLEAN PressureCallbackValidated;

    /// Periodic maintenance timer
    KTIMER MaintenanceTimer;
    KDPC MaintenanceDpc;
    ULONG MaintenanceIntervalMs;
    BOOLEAN MaintenanceEnabled;

    /// Work item for deferred pressure callback
    PIO_WORKITEM PressureWorkItem;
    PDEVICE_OBJECT DeviceObject;

    /// Pending pressure notification (for work item)
    volatile LL_MEMORY_PRESSURE PendingPressureLevel;
    volatile LONG64 PendingCurrentMemory;
    volatile LONG64 PendingMemoryLimit;
    volatile LONG PressureWorkPending;

    /// Self-tuning enabled
    BOOLEAN SelfTuningEnabled;

    /// Debug mode enabled
    BOOLEAN DebugMode;

    /// Reserved
    UCHAR Reserved2;

    /// Spinlock for fast operations
    KSPIN_LOCK FastLock;

    /// Reference count for safe shutdown
    volatile LONG RefCount;

    /// Shutdown event
    KEVENT ShutdownEvent;

} LL_MANAGER, *PLL_MANAGER;

// ============================================================================
// MANAGER INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the lookaside list manager.
 *
 * Creates and initializes the central lookaside list manager. Must be
 * called during driver initialization before any lookaside operations.
 *
 * @param Manager   Receives pointer to initialized manager
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlInitialize(
    _Out_ PLL_MANAGER* Manager
    );

/**
 * @brief Initialize manager with device object for work items.
 *
 * @param Manager       Receives pointer to initialized manager
 * @param DeviceObject  Device object for work item operations
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
LlInitializeEx(
    _Out_ PLL_MANAGER* Manager,
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

/**
 * @brief Shutdown the lookaside list manager.
 *
 * Destroys all managed lookaside lists and releases all resources.
 * Waits for all outstanding allocations to be freed.
 *
 * @param Manager   Manager to shutdown (set to NULL on return)
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlShutdown(
    _Inout_ PLL_MANAGER Manager
    );

// ============================================================================
// LOOKASIDE LIST CREATION AND DESTRUCTION
// ============================================================================

/**
 * @brief Create a new lookaside list.
 *
 * Creates a managed lookaside list for fixed-size allocations.
 * The list is automatically tracked and cleaned up on manager shutdown.
 *
 * @param Manager   Lookaside manager
 * @param Name      Human-readable name (max 31 chars)
 * @param Tag       Pool tag for allocations
 * @param EntrySize Size of each entry
 * @param IsPaged   TRUE for paged pool, FALSE for non-paged
 * @param Lookaside Receives pointer to created lookaside
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
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

/**
 * @brief Create a lookaside list with extended options.
 *
 * @param Manager   Lookaside manager
 * @param Name      Human-readable name
 * @param Tag       Pool tag
 * @param EntrySize Entry size
 * @param IsPaged   TRUE for paged pool
 * @param Depth     Initial depth (0 for default)
 * @param Flags     Allocation flags
 * @param Lookaside Receives created lookaside
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
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

/**
 * @brief Destroy a lookaside list.
 *
 * Destroys the lookaside list and frees all cached entries.
 * Waits for all outstanding allocations to be returned.
 *
 * @param Manager   Lookaside manager
 * @param Lookaside Lookaside list to destroy
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlDestroyLookaside(
    _In_ PLL_MANAGER Manager,
    _In_ PLL_LOOKASIDE Lookaside
    );

// ============================================================================
// REFERENCE COUNTING
// ============================================================================

/**
 * @brief Acquire reference to lookaside list.
 *
 * Thread-safe reference increment using atomic CAS loop.
 * Must be called before using a lookaside obtained from enumeration.
 *
 * @param Lookaside Lookaside to reference
 *
 * @return TRUE if reference acquired, FALSE if lookaside is being destroyed
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LlReferenceLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    );

/**
 * @brief Release reference to lookaside list.
 *
 * Decrements reference count. When count reaches zero and list is
 * marked for removal, the list is freed.
 *
 * @param Lookaside Lookaside to release
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlReleaseLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    );

// ============================================================================
// ALLOCATION AND DEALLOCATION
// ============================================================================

/**
 * @brief Allocate from lookaside list.
 *
 * Allocates a fixed-size block from the lookaside list.
 * Returns zeroed memory for security.
 *
 * @param Lookaside Lookaside list to allocate from
 *
 * @return Pointer to allocated block, or NULL on failure
 *
 * @irql <= DISPATCH_LEVEL for non-paged
 * @irql <= APC_LEVEL for paged
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
PVOID
LlAllocate(
    _In_ PLL_LOOKASIDE Lookaside
    );

/**
 * @brief Allocate with extended options.
 *
 * @param Lookaside Lookaside list
 * @param Flags     Allocation flags
 *
 * @return Pointer to allocated block, or NULL on failure
 *
 * @irql Depends on pool type
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
PVOID
LlAllocateEx(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ ULONG Flags
    );

/**
 * @brief Free to lookaside list.
 *
 * Returns a block to the lookaside list cache.
 *
 * @param Lookaside Lookaside list
 * @param Block     Block to free
 *
 * @irql <= DISPATCH_LEVEL for non-paged
 * @irql <= APC_LEVEL for paged
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    );

/**
 * @brief Secure free with memory wiping.
 *
 * Securely wipes the block before returning to cache.
 * Use for security-sensitive data.
 *
 * @param Lookaside Lookaside list
 * @param Block     Block to securely free
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LlSecureFree(
    _In_ PLL_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Block
    );

// ============================================================================
// STATISTICS AND MONITORING
// ============================================================================

/**
 * @brief Get lookaside list statistics.
 *
 * @param Lookaside     Lookaside list
 * @param Statistics    Receives statistics copy
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetStatistics(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PLL_STATISTICS Statistics
    );

/**
 * @brief Get hit/miss ratio.
 *
 * @param Lookaside Lookaside list
 * @param Hits      Receives hit count
 * @param Misses    Receives miss count
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetHitMissRatio(
    _In_ PLL_LOOKASIDE Lookaside,
    _Out_ PULONG64 Hits,
    _Out_ PULONG64 Misses
    );

/**
 * @brief Get global manager statistics.
 *
 * @param Manager       Lookaside manager
 * @param Statistics    Receives global statistics
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlGetGlobalStatistics(
    _In_ PLL_MANAGER Manager,
    _Out_ PLL_GLOBAL_STATISTICS Statistics
    );

/**
 * @brief Reset statistics for a lookaside list.
 *
 * @param Lookaside Lookaside list
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlResetStatistics(
    _In_ PLL_LOOKASIDE Lookaside
    );

/**
 * @brief Reset global statistics.
 *
 * @param Manager   Lookaside manager
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
LlResetGlobalStatistics(
    _In_ PLL_MANAGER Manager
    );

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

/**
 * @brief Set memory limit for manager.
 *
 * @param Manager       Lookaside manager
 * @param MemoryLimit   Maximum memory in bytes (0 = unlimited)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlSetMemoryLimit(
    _In_ PLL_MANAGER Manager,
    _In_ LONG64 MemoryLimit
    );

/**
 * @brief Get current memory usage.
 *
 * @param Manager   Lookaside manager
 *
 * @return Current memory usage in bytes
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
LONG64
LlGetMemoryUsage(
    _In_ PLL_MANAGER Manager
    );

/**
 * @brief Register memory pressure callback.
 *
 * @param Manager   Lookaside manager
 * @param Callback  Callback function (MUST be in non-paged memory)
 * @param Context   Callback context
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 *
 * @note The callback will be invoked at PASSIVE_LEVEL via work item
 *       when pressure changes are detected at DISPATCH_LEVEL.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlRegisterPressureCallback(
    _In_ PLL_MANAGER Manager,
    _In_ LL_PRESSURE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Trim cached entries to reduce memory.
 *
 * Forces reduction of cached lookaside entries.
 *
 * @param Manager   Lookaside manager
 *
 * @return Number of bytes freed
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
LONG64
LlTrimCaches(
    _In_ PLL_MANAGER Manager
    );

// ============================================================================
// MAINTENANCE AND TUNING
// ============================================================================

/**
 * @brief Enable periodic maintenance.
 *
 * @param Manager       Lookaside manager
 * @param IntervalMs    Maintenance interval in milliseconds
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlEnableMaintenance(
    _In_ PLL_MANAGER Manager,
    _In_ ULONG IntervalMs
    );

/**
 * @brief Disable periodic maintenance.
 *
 * @param Manager   Lookaside manager
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlDisableMaintenance(
    _In_ PLL_MANAGER Manager
    );

/**
 * @brief Enable self-tuning of lookaside depths.
 *
 * @param Manager   Lookaside manager
 * @param Enable    TRUE to enable, FALSE to disable
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlEnableSelfTuning(
    _In_ PLL_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

// ============================================================================
// ENUMERATION
// ============================================================================

/**
 * @brief Enumerate all lookaside lists.
 *
 * @param Manager   Lookaside manager
 * @param Callback  Enumeration callback (return FALSE to stop)
 * @param Context   Callback context
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 *
 * @note Callback must NOT destroy the lookaside being enumerated.
 *       Safe enumeration captures next pointer before callback.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlEnumerateLookasides(
    _In_ PLL_MANAGER Manager,
    _In_ LL_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Find lookaside by name.
 *
 * @param Manager   Lookaside manager
 * @param Name      Lookaside name to find
 * @param Lookaside Receives lookaside if found (caller must release)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 *
 * @irql <= APC_LEVEL
 *
 * @note Caller must call LlReleaseLookaside when done with returned lookaside
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LlFindByName(
    _In_ PLL_MANAGER Manager,
    _In_ PCSTR Name,
    _Out_ PLL_LOOKASIDE* Lookaside
    );

/**
 * @brief Find lookaside by tag.
 *
 * @param Manager   Lookaside manager
 * @param Tag       Pool tag to find
 * @param Lookaside Receives lookaside if found (caller must release)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 *
 * @irql <= APC_LEVEL
 *
 * @note Caller must call LlReleaseLookaside when done with returned lookaside
 */
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

/**
 * @brief Enable debug mode.
 *
 * Enables additional validation and logging.
 *
 * @param Manager   Lookaside manager
 * @param Enable    TRUE to enable debug mode
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LlSetDebugMode(
    _In_ PLL_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

/**
 * @brief Validate lookaside list integrity.
 *
 * @param Lookaside Lookaside list to validate
 *
 * @return TRUE if valid, FALSE if corrupted
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LlValidateLookaside(
    _In_ PLL_LOOKASIDE Lookaside
    );

/**
 * @brief Dump lookaside diagnostics to debug output.
 *
 * @param Manager   Lookaside manager
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
LlDumpDiagnostics(
    _In_ PLL_MANAGER Manager
    );

// ============================================================================
// LEGACY COMPATIBILITY (wrapper for old interface)
// ============================================================================

/**
 * @brief Legacy stats retrieval (compatibility wrapper)
 */
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

/**
 * @brief Calculate hit rate percentage (overflow-safe).
 */
FORCEINLINE
ULONG
LlCalculateHitRate(
    _In_ LONG64 Hits,
    _In_ LONG64 Misses
    )
{
    LONG64 Total = Hits + Misses;
    if (Total == 0) {
        return 0;
    }
    //
    // Use 64-bit multiplication to prevent overflow
    // Cast to ULONG64 before multiplying to ensure no signed overflow
    //
    return (ULONG)(((ULONG64)Hits * 100ULL) / (ULONG64)Total);
}

/**
 * @brief Check if lookaside is valid (fast path validation).
 *
 * @note This is a quick validity check. For operations that need
 *       to safely use the lookaside, use LlReferenceLookaside.
 */
FORCEINLINE
BOOLEAN
LlIsValid(
    _In_opt_ PLL_LOOKASIDE Lookaside
    )
{
    LL_STATE State;

    if (Lookaside == NULL) {
        return FALSE;
    }

    //
    // Use volatile read to ensure we see current value
    //
    if (Lookaside->Magic != LL_ENTRY_MAGIC) {
        return FALSE;
    }

    State = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Lookaside->State,
        LlStateActive,
        LlStateActive
    );

    if (State != LlStateActive) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Check if manager is valid.
 */
FORCEINLINE
BOOLEAN
LlManagerIsValid(
    _In_opt_ PLL_MANAGER Manager
    )
{
    LL_STATE State;

    if (Manager == NULL) {
        return FALSE;
    }

    if (Manager->Magic != LL_MANAGER_MAGIC) {
        return FALSE;
    }

    if (!Manager->Initialized) {
        return FALSE;
    }

    //
    // Atomic read of state
    //
    State = (LL_STATE)InterlockedCompareExchange(
        (volatile LONG*)&Manager->State,
        LlStateActive,
        LlStateActive
    );

    if (State != LlStateActive) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Safe size addition with overflow check.
 */
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

/**
 * @brief Safe size multiplication with overflow check.
 */
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
