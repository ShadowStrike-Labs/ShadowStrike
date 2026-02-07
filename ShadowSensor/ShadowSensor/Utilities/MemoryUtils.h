/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL MEMORY UTILITIES
 * ============================================================================
 *
 * @file MemoryUtils.h
 * @brief Enterprise-grade memory management for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level memory handling with:
 * - Safe pool allocation with automatic zeroing (NX pools)
 * - Lookaside list management for high-frequency allocations
 * - MDL (Memory Descriptor List) operations for safe user/kernel transfers
 * - Secure memory wiping for sensitive data
 * - Memory mapping utilities for cross-process operations
 * - Quota-aware allocations to prevent resource exhaustion
 * - Non-paged pool tracking and leak detection
 * - Safe probe and capture for user-mode buffers
 * - Aligned allocation support for DMA/cache optimization
 *
 * Security Guarantees:
 * - All allocations are zeroed to prevent information leaks
 * - Pool tags enable forensic analysis and leak detection
 * - Integer overflow checks on all size calculations
 * - IRQL validation on all operations
 * - Secure wipe uses volatile writes to prevent optimization
 * - User buffer probing prevents kernel exploitation
 *
 * Performance Optimizations:
 * - Lookaside lists for fixed-size frequent allocations
 * - Aligned allocations for cache-line optimization
 * - Non-paged pool minimization strategies
 * - IRQL-aware operation selection
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (safe memory mapping)
 * - T1106: Native API (secure buffer handling)
 * - T1003: Credential Dumping (secure memory wipe)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_MEMORY_UTILS_H_
#define _SHADOWSTRIKE_MEMORY_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Primary pool tag: 'SsFt' = ShadowStrike Filter (little-endian)
 */
#define SHADOWSTRIKE_POOL_TAG           'tFsS'

/**
 * @brief Pool tag for MDL allocations
 */
#define SHADOWSTRIKE_MDL_TAG            'lDsS'

/**
 * @brief Pool tag for lookaside allocations
 */
#define SHADOWSTRIKE_LOOKASIDE_TAG      'aLsS'

/**
 * @brief Pool tag for context allocations
 */
#define SHADOWSTRIKE_CONTEXT_TAG        'xCsS'

/**
 * @brief Pool tag for buffer allocations
 */
#define SHADOWSTRIKE_BUFFER_TAG         'fBsS'

/**
 * @brief Pool tag for temporary allocations
 */
#define SHADOWSTRIKE_TEMP_TAG           'pTsS'

/**
 * @brief Pool tag for security-sensitive allocations
 */
#define SHADOWSTRIKE_SECURE_TAG         'cSsS'

/**
 * @brief Pool tag for aligned allocations
 */
#define SHADOWSTRIKE_ALIGNED_TAG        'lAsS'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum single allocation size (256 MB safety limit)
 */
#define SHADOWSTRIKE_MAX_ALLOCATION_SIZE    (256 * 1024 * 1024)

/**
 * @brief Default lookaside list depth
 */
#define SHADOWSTRIKE_LOOKASIDE_DEPTH        256

/**
 * @brief Minimum lookaside list depth
 */
#define SHADOWSTRIKE_MIN_LOOKASIDE_DEPTH    16

/**
 * @brief Maximum lookaside list depth
 */
#define SHADOWSTRIKE_MAX_LOOKASIDE_DEPTH    4096

/**
 * @brief Cache line size for alignment
 */
#define SHADOWSTRIKE_CACHE_LINE_SIZE        64

/**
 * @brief Page alignment size
 */
#define SHADOWSTRIKE_PAGE_ALIGNMENT         PAGE_SIZE

/**
 * @brief Secure wipe pattern (DoD 5220.22-M compliant)
 */
#define SHADOWSTRIKE_WIPE_PATTERN_1         0x00
#define SHADOWSTRIKE_WIPE_PATTERN_2         0xFF
#define SHADOWSTRIKE_WIPE_PATTERN_3         0xAA

// ============================================================================
// ALLOCATION CONVENIENCE MACROS
// ============================================================================

/**
 * @brief Allocate from NonPagedPoolNx with default tag
 * @param Size Number of bytes to allocate
 * @return Pointer to allocated memory or NULL
 */
#define ShadowStrikeAllocate(Size) \
    ShadowStrikeAllocatePoolWithTag(NonPagedPoolNx, (Size), SHADOWSTRIKE_POOL_TAG)

/**
 * @brief Allocate from PagedPool with default tag
 * @param Size Number of bytes to allocate
 * @return Pointer to allocated memory or NULL
 */
#define ShadowStrikeAllocatePaged(Size) \
    ShadowStrikeAllocatePoolWithTag(PagedPool, (Size), SHADOWSTRIKE_POOL_TAG)

/**
 * @brief Allocate with custom tag from NonPagedPoolNx
 * @param Size Number of bytes to allocate
 * @param Tag Pool tag for tracking
 * @return Pointer to allocated memory or NULL
 */
#define ShadowStrikeAllocateWithTag(Size, Tag) \
    ShadowStrikeAllocatePoolWithTag(NonPagedPoolNx, (Size), (Tag))

/**
 * @brief Allocate paged memory with custom tag
 * @param Size Number of bytes to allocate
 * @param Tag Pool tag for tracking
 * @return Pointer to allocated memory or NULL
 */
#define ShadowStrikeAllocatePagedWithTag(Size, Tag) \
    ShadowStrikeAllocatePoolWithTag(PagedPool, (Size), (Tag))

/**
 * @brief Free memory with default tag
 * @param P Pointer to memory to free
 */
#define ShadowStrikeFree(P) \
    ShadowStrikeFreePoolWithTag((P), SHADOWSTRIKE_POOL_TAG)

/**
 * @brief Safe free with NULL check and pointer clear
 * @param P Pointer variable to free and NULL
 */
#define ShadowStrikeSafeFree(P) \
    do { \
        if ((P) != NULL) { \
            ShadowStrikeFreePool(P); \
            (P) = NULL; \
        } \
    } while (0)

/**
 * @brief Safe free with tag, NULL check and pointer clear
 * @param P Pointer variable to free and NULL
 * @param Tag Pool tag
 */
#define ShadowStrikeSafeFreeWithTag(P, Tag) \
    do { \
        if ((P) != NULL) { \
            ShadowStrikeFreePoolWithTag((P), (Tag)); \
            (P) = NULL; \
        } \
    } while (0)

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Memory allocation flags
 */
typedef enum _SHADOWSTRIKE_ALLOC_FLAGS {
    /// No special flags
    ShadowAllocNone             = 0x00000000,

    /// Zero memory on allocation (default behavior)
    ShadowAllocZeroMemory       = 0x00000001,

    /// Raise exception on failure instead of returning NULL
    ShadowAllocRaiseOnFailure   = 0x00000002,

    /// Allocation must succeed (retry with lower priority)
    ShadowAllocMustSucceed      = 0x00000004,

    /// Align to cache line boundary
    ShadowAllocCacheAligned     = 0x00000008,

    /// Align to page boundary
    ShadowAllocPageAligned      = 0x00000010,

    /// Use quota charging (for user-initiated operations)
    ShadowAllocChargeQuota      = 0x00000020,

    /// Security sensitive - will be securely wiped on free
    ShadowAllocSecure           = 0x00000040,

    /// Contiguous physical memory required
    ShadowAllocContiguous       = 0x00000080

} SHADOWSTRIKE_ALLOC_FLAGS;

/**
 * @brief MDL operation type
 */
typedef enum _SHADOWSTRIKE_MDL_OPERATION {
    /// Read from user buffer
    ShadowMdlRead               = 0,

    /// Write to user buffer
    ShadowMdlWrite              = 1,

    /// Read/Write access
    ShadowMdlReadWrite          = 2

} SHADOWSTRIKE_MDL_OPERATION;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Lookaside list wrapper with statistics
 */
typedef struct _SHADOWSTRIKE_LOOKASIDE {
    /// Actual lookaside list (non-paged)
    NPAGED_LOOKASIDE_LIST NonPagedList;

    /// Actual lookaside list (paged)
    PAGED_LOOKASIDE_LIST PagedList;

    /// Is this a paged pool lookaside
    BOOLEAN IsPaged;

    /// Entry size
    SIZE_T EntrySize;

    /// Pool tag
    ULONG PoolTag;

    /// Initialization flag
    BOOLEAN Initialized;

    /// Padding
    UCHAR Reserved[2];

    /// Statistics: allocations
    volatile LONG64 TotalAllocations;

    /// Statistics: frees
    volatile LONG64 TotalFrees;

    /// Statistics: current outstanding
    volatile LONG CurrentOutstanding;

    /// Statistics: peak outstanding
    volatile LONG PeakOutstanding;

    /// Statistics: allocation failures
    volatile LONG64 AllocationFailures;

} SHADOWSTRIKE_LOOKASIDE, *PSHADOWSTRIKE_LOOKASIDE;

/**
 * @brief Safe buffer descriptor for user-mode data
 */
typedef struct _SHADOWSTRIKE_SAFE_BUFFER {
    /// Kernel-mode copy of data
    PVOID KernelBuffer;

    /// Original user-mode address (for reference only)
    PVOID OriginalUserBuffer;

    /// Buffer size
    SIZE_T Size;

    /// Pool tag used for allocation
    ULONG PoolTag;

    /// Was this a paged allocation
    BOOLEAN IsPaged;

    /// Is this a secure buffer (needs wiping)
    BOOLEAN IsSecure;

    /// Padding
    UCHAR Reserved[2];

} SHADOWSTRIKE_SAFE_BUFFER, *PSHADOWSTRIKE_SAFE_BUFFER;

/**
 * @brief Mapped memory descriptor
 */
typedef struct _SHADOWSTRIKE_MAPPED_MEMORY {
    /// MDL for the mapping
    PMDL Mdl;

    /// System address of mapped memory
    PVOID MappedAddress;

    /// Original address
    PVOID OriginalAddress;

    /// Size of mapping
    SIZE_T Size;

    /// Was locked successfully
    BOOLEAN IsLocked;

    /// Access mode (KernelMode or UserMode)
    KPROCESSOR_MODE AccessMode;

    /// Operation type
    SHADOWSTRIKE_MDL_OPERATION Operation;

    /// Padding
    UCHAR Reserved;

} SHADOWSTRIKE_MAPPED_MEMORY, *PSHADOWSTRIKE_MAPPED_MEMORY;

/**
 * @brief Aligned allocation header (internal use)
 */
typedef struct _SHADOWSTRIKE_ALIGNED_HEADER {
    /// Original unaligned pointer
    PVOID OriginalPointer;

    /// Requested alignment
    SIZE_T Alignment;

    /// Magic value for validation
    ULONG Magic;

    /// Pool tag
    ULONG PoolTag;

} SHADOWSTRIKE_ALIGNED_HEADER, *PSHADOWSTRIKE_ALIGNED_HEADER;

#define SHADOWSTRIKE_ALIGNED_MAGIC  0x4E474C41  // 'ALGN'

// ============================================================================
// MEMORY POOL SUBSYSTEM MANAGEMENT
// ============================================================================

/**
 * @brief Initialize the memory utilities subsystem.
 *
 * Must be called during driver initialization before any memory operations.
 * Sets up internal tracking structures and validates system state.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInitializeMemoryUtils(
    VOID
    );

/**
 * @brief Cleanup the memory utilities subsystem.
 *
 * Must be called during driver unload. Validates no outstanding allocations
 * and releases any internal resources.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupMemoryUtils(
    VOID
    );

// ============================================================================
// CORE ALLOCATION FUNCTIONS
// ============================================================================

/**
 * @brief Allocate pool memory with tag.
 *
 * Enterprise-grade allocation with:
 * - Automatic zeroing of allocated memory
 * - Size validation to prevent integer overflow
 * - IRQL validation for pool type
 * - Allocation tracking for leak detection
 *
 * @param PoolType     Pool type (NonPagedPoolNx recommended)
 * @param NumberOfBytes    Size in bytes to allocate
 * @param Tag          Pool tag for tracking
 *
 * @return Pointer to allocated memory, or NULL on failure
 *
 * @irql <= DISPATCH_LEVEL for NonPaged
 * @irql <= APC_LEVEL for Paged
 *
 * @note Always use NonPagedPoolNx instead of NonPagedPool for security
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(PoolType == PagedPool, _IRQL_requires_max_(APC_LEVEL))
_Ret_maybenull_
_Post_writable_byte_size_(NumberOfBytes)
PVOID
ShadowStrikeAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

/**
 * @brief Allocate pool memory with extended flags.
 *
 * @param PoolType     Pool type
 * @param NumberOfBytes    Size in bytes
 * @param Tag          Pool tag
 * @param Flags        Allocation flags (SHADOWSTRIKE_ALLOC_FLAGS)
 *
 * @return Pointer to allocated memory, or NULL on failure
 *
 * @irql Depends on pool type and flags
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(PoolType == PagedPool, _IRQL_requires_max_(APC_LEVEL))
_Ret_maybenull_
_Post_writable_byte_size_(NumberOfBytes)
PVOID
ShadowStrikeAllocatePoolWithFlags(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _In_ ULONG Flags
    );

/**
 * @brief Allocate cache-aligned memory.
 *
 * Useful for DMA buffers and performance-critical data structures
 * to avoid false sharing and cache line splits.
 *
 * @param PoolType     Pool type
 * @param NumberOfBytes    Size in bytes
 * @param Alignment    Required alignment (must be power of 2)
 * @param Tag          Pool tag
 *
 * @return Aligned pointer, or NULL on failure
 *
 * @irql Depends on pool type
 *
 * @note Must be freed with ShadowStrikeFreeAligned
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(PoolType == PagedPool, _IRQL_requires_max_(APC_LEVEL))
_Ret_maybenull_
PVOID
ShadowStrikeAllocateAligned(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ SIZE_T Alignment,
    _In_ ULONG Tag
    );

/**
 * @brief Reallocate memory to new size.
 *
 * Allocates new buffer, copies existing data, and frees old buffer.
 * If new allocation fails, original buffer is preserved.
 *
 * @param OldBuffer    Existing buffer (can be NULL)
 * @param OldSize      Size of existing buffer
 * @param NewSize      New size required
 * @param Tag          Pool tag
 * @param PoolType     Pool type for new allocation
 *
 * @return New buffer pointer, or NULL on failure (original preserved)
 *
 * @irql Depends on pool type
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(PoolType == PagedPool, _IRQL_requires_max_(APC_LEVEL))
_Ret_maybenull_
PVOID
ShadowStrikeReallocate(
    _In_opt_ PVOID OldBuffer,
    _In_ SIZE_T OldSize,
    _In_ SIZE_T NewSize,
    _In_ ULONG Tag,
    _In_ POOL_TYPE PoolType
    );

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

/**
 * @brief Free pool memory.
 *
 * @param P    Pointer to free (NULL is safely ignored)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreePool(
    _In_opt_ _Post_ptr_invalid_ PVOID P
    );

/**
 * @brief Free pool memory with tag verification.
 *
 * @param P    Pointer to free (NULL is safely ignored)
 * @param Tag  Pool tag (must match allocation tag)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreePoolWithTag(
    _In_opt_ _Post_ptr_invalid_ PVOID P,
    _In_ ULONG Tag
    );

/**
 * @brief Free aligned memory.
 *
 * @param P    Aligned pointer from ShadowStrikeAllocateAligned
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeAligned(
    _In_opt_ _Post_ptr_invalid_ PVOID P
    );

/**
 * @brief Securely free memory with content wiping.
 *
 * Overwrites memory content before freeing to prevent sensitive
 * data recovery. Uses volatile writes to prevent compiler optimization.
 *
 * @param P        Pointer to free
 * @param Size     Size of allocation
 * @param Tag      Pool tag
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeSecureFree(
    _In_opt_ _Post_ptr_invalid_ PVOID P,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
    );

// ============================================================================
// LOOKASIDE LIST MANAGEMENT
// ============================================================================

/**
 * @brief Initialize a lookaside list.
 *
 * Creates a high-performance lookaside list for fixed-size allocations.
 * Much faster than pool allocations for frequently allocated objects.
 *
 * @param Lookaside    Lookaside structure to initialize
 * @param EntrySize    Size of each entry
 * @param Tag          Pool tag
 * @param Depth        Maximum cached entries (0 = system default)
 * @param IsPaged      TRUE for paged pool, FALSE for non-paged
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeLookasideInit(
    _Out_ PSHADOWSTRIKE_LOOKASIDE Lookaside,
    _In_ SIZE_T EntrySize,
    _In_ ULONG Tag,
    _In_ USHORT Depth,
    _In_ BOOLEAN IsPaged
    );

/**
 * @brief Allocate from lookaside list.
 *
 * @param Lookaside    Initialized lookaside structure
 *
 * @return Pointer to entry, or NULL on failure
 *
 * @irql <= DISPATCH_LEVEL for non-paged
 * @irql <= APC_LEVEL for paged
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
PVOID
ShadowStrikeLookasideAllocate(
    _Inout_ PSHADOWSTRIKE_LOOKASIDE Lookaside
    );

/**
 * @brief Free to lookaside list.
 *
 * @param Lookaside    Initialized lookaside structure
 * @param Entry        Entry to free
 *
 * @irql <= DISPATCH_LEVEL for non-paged
 * @irql <= APC_LEVEL for paged
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeLookasideFree(
    _Inout_ PSHADOWSTRIKE_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Entry
    );

/**
 * @brief Cleanup lookaside list.
 *
 * Releases all cached entries. Must be called before driver unload.
 *
 * @param Lookaside    Lookaside structure to cleanup
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLookasideCleanup(
    _Inout_ PSHADOWSTRIKE_LOOKASIDE Lookaside
    );

/**
 * @brief Get lookaside list statistics.
 *
 * @param Lookaside        Lookaside structure
 * @param Allocations      Receives total allocations
 * @param Frees            Receives total frees
 * @param Outstanding      Receives current outstanding count
 * @param Failures         Receives allocation failure count
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeLookasideGetStats(
    _In_ PSHADOWSTRIKE_LOOKASIDE Lookaside,
    _Out_opt_ PLONG64 Allocations,
    _Out_opt_ PLONG64 Frees,
    _Out_opt_ PLONG Outstanding,
    _Out_opt_ PLONG64 Failures
    );

// ============================================================================
// USER-MODE BUFFER OPERATIONS
// ============================================================================

/**
 * @brief Safely capture user-mode buffer to kernel memory.
 *
 * Probes and copies user-mode buffer to kernel memory for safe access.
 * Prevents TOCTOU attacks and ensures data consistency.
 *
 * @param UserBuffer       User-mode buffer address
 * @param BufferSize       Size of buffer
 * @param ProbeAlignment   Alignment for probe (usually sizeof(UCHAR))
 * @param SafeBuffer       Receives safe buffer descriptor
 * @param PoolType         Pool type for kernel copy
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL (due to user-mode access)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeCaptureUserBuffer(
    _In_reads_bytes_(BufferSize) PVOID UserBuffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG ProbeAlignment,
    _Out_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer,
    _In_ POOL_TYPE PoolType
    );

/**
 * @brief Safely capture user-mode buffer (security-sensitive version).
 *
 * Same as ShadowStrikeCaptureUserBuffer but marks buffer for secure
 * wiping on release.
 *
 * @param UserBuffer       User-mode buffer address
 * @param BufferSize       Size of buffer
 * @param SafeBuffer       Receives safe buffer descriptor
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeCaptureUserBufferSecure(
    _In_reads_bytes_(BufferSize) PVOID UserBuffer,
    _In_ SIZE_T BufferSize,
    _Out_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer
    );

/**
 * @brief Release captured user buffer.
 *
 * Frees the kernel-mode copy. If buffer was captured with secure flag,
 * performs secure wipe before freeing.
 *
 * @param SafeBuffer   Safe buffer to release
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseUserBuffer(
    _Inout_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer
    );

/**
 * @brief Probe user-mode buffer for read access.
 *
 * Validates user-mode buffer is accessible without copying.
 * Use when you need to validate but will access via MDL.
 *
 * @param Buffer       User-mode buffer
 * @param Length       Buffer length
 * @param Alignment    Required alignment
 *
 * @return STATUS_SUCCESS if accessible
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProbeUserBufferRead(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
    );

/**
 * @brief Probe user-mode buffer for write access.
 *
 * @param Buffer       User-mode buffer
 * @param Length       Buffer length
 * @param Alignment    Required alignment
 *
 * @return STATUS_SUCCESS if writable
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProbeUserBufferWrite(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
    );

// ============================================================================
// MDL OPERATIONS
// ============================================================================

/**
 * @brief Create and lock MDL for buffer.
 *
 * Creates MDL, probes, and locks pages for safe kernel access.
 *
 * @param Buffer           Buffer to map
 * @param Length           Buffer length
 * @param AccessMode       Access mode (UserMode or KernelMode)
 * @param Operation        Read, Write, or ReadWrite
 * @param MappedMemory     Receives mapped memory descriptor
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL for UserMode, <= DISPATCH_LEVEL for KernelMode
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(AccessMode == UserMode, _IRQL_requires_(PASSIVE_LEVEL))
NTSTATUS
ShadowStrikeMapMemory(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ SHADOWSTRIKE_MDL_OPERATION Operation,
    _Out_ PSHADOWSTRIKE_MAPPED_MEMORY MappedMemory
    );

/**
 * @brief Map memory into system address space.
 *
 * Maps already-locked MDL pages to system virtual address.
 *
 * @param MappedMemory     Mapped memory descriptor (MDL must be locked)
 * @param CacheType        Cache type for mapping
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeMapToSystemAddress(
    _Inout_ PSHADOWSTRIKE_MAPPED_MEMORY MappedMemory,
    _In_ MEMORY_CACHING_TYPE CacheType
    );

/**
 * @brief Unmap and free mapped memory.
 *
 * @param MappedMemory     Mapped memory to release
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeUnmapMemory(
    _Inout_ PSHADOWSTRIKE_MAPPED_MEMORY MappedMemory
    );

/**
 * @brief Create MDL for kernel buffer.
 *
 * Simple MDL creation for kernel-mode buffers.
 *
 * @param Buffer       Kernel buffer
 * @param Length       Buffer length
 * @param Mdl          Receives MDL pointer
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeCreateMdl(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _Out_ PMDL* Mdl
    );

/**
 * @brief Free MDL.
 *
 * @param Mdl  MDL to free
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeMdl(
    _In_opt_ _Post_ptr_invalid_ PMDL Mdl
    );

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

/**
 * @brief Securely zero memory.
 *
 * Uses volatile writes to prevent compiler optimization.
 * Memory barrier ensures completion before return.
 *
 * @param Destination  Memory to zero
 * @param Length       Number of bytes
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeSecureZeroMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
    );

/**
 * @brief Securely wipe memory with multiple patterns.
 *
 * DoD 5220.22-M compliant secure wipe:
 * Pass 1: 0x00
 * Pass 2: 0xFF
 * Pass 3: 0xAA
 *
 * @param Destination  Memory to wipe
 * @param Length       Number of bytes
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeSecureWipeMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
    );

/**
 * @brief Compare memory in constant time.
 *
 * Prevents timing side-channel attacks when comparing secrets.
 *
 * @param Buffer1  First buffer
 * @param Buffer2  Second buffer
 * @param Length   Number of bytes to compare
 *
 * @return TRUE if equal, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeSecureCompare(
    _In_reads_bytes_(Length) const VOID* Buffer1,
    _In_reads_bytes_(Length) const VOID* Buffer2,
    _In_ SIZE_T Length
    );

// ============================================================================
// MEMORY VALIDATION UTILITIES
// ============================================================================

/**
 * @brief Check if address is valid kernel-mode address.
 *
 * @param Address  Address to validate
 *
 * @return TRUE if valid kernel address
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsKernelAddress(
    _In_ PVOID Address
    );

/**
 * @brief Check if address is valid user-mode address.
 *
 * @param Address  Address to validate
 *
 * @return TRUE if valid user address
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsUserAddress(
    _In_ PVOID Address
    );

/**
 * @brief Validate memory range is accessible.
 *
 * @param Address      Start address
 * @param Length       Length in bytes
 * @param WriteAccess  TRUE to validate write access
 *
 * @return TRUE if entire range is accessible
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsMemoryValid(
    _In_ PVOID Address,
    _In_ SIZE_T Length,
    _In_ BOOLEAN WriteAccess
    );

/**
 * @brief Check if allocation size is safe.
 *
 * Validates size is within limits and won't cause integer overflow.
 *
 * @param Size     Requested size
 * @param Count    Number of items (for array allocations)
 *
 * @return TRUE if allocation is safe
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsSafeAllocationSize(
    _In_ SIZE_T Size,
    _In_ SIZE_T Count
    );

// ============================================================================
// PHYSICAL MEMORY OPERATIONS
// ============================================================================

/**
 * @brief Get physical address for virtual address.
 *
 * @param VirtualAddress   Virtual address
 *
 * @return Physical address (0 if invalid)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PHYSICAL_ADDRESS
ShadowStrikeGetPhysicalAddress(
    _In_ PVOID VirtualAddress
    );

/**
 * @brief Allocate contiguous physical memory.
 *
 * For DMA operations requiring physically contiguous memory.
 *
 * @param NumberOfBytes        Size required
 * @param LowestAcceptable     Lowest physical address
 * @param HighestAcceptable    Highest physical address
 * @param BoundaryAddressMultiple  Alignment boundary
 *
 * @return Virtual address of allocated memory, or NULL
 *
 * @irql <= DISPATCH_LEVEL
 */
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
PVOID
ShadowStrikeAllocateContiguous(
    _In_ SIZE_T NumberOfBytes,
    _In_ PHYSICAL_ADDRESS LowestAcceptable,
    _In_ PHYSICAL_ADDRESS HighestAcceptable,
    _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple
    );

/**
 * @brief Free contiguous physical memory.
 *
 * @param BaseAddress  Virtual address from ShadowStrikeAllocateContiguous
 * @param NumberOfBytes    Size of allocation
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeContiguous(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes
    );

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Align size up to specified alignment.
 */
FORCEINLINE
SIZE_T
ShadowStrikeAlignUp(
    _In_ SIZE_T Value,
    _In_ SIZE_T Alignment
    )
{
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

/**
 * @brief Align size down to specified alignment.
 */
FORCEINLINE
SIZE_T
ShadowStrikeAlignDown(
    _In_ SIZE_T Value,
    _In_ SIZE_T Alignment
    )
{
    return Value & ~(Alignment - 1);
}

/**
 * @brief Check if value is power of 2.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsPowerOf2(
    _In_ SIZE_T Value
    )
{
    return (Value != 0) && ((Value & (Value - 1)) == 0);
}

/**
 * @brief Check if pointer is aligned.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsAligned(
    _In_ PVOID Pointer,
    _In_ SIZE_T Alignment
    )
{
    return ((ULONG_PTR)Pointer & (Alignment - 1)) == 0;
}

/**
 * @brief Calculate array allocation size with overflow check.
 *
 * @param ElementSize   Size of each element
 * @param ElementCount  Number of elements
 * @param TotalSize     Receives total size, or 0 on overflow
 *
 * @return TRUE if no overflow, FALSE on overflow
 */
FORCEINLINE
BOOLEAN
ShadowStrikeSafeMultiply(
    _In_ SIZE_T ElementSize,
    _In_ SIZE_T ElementCount,
    _Out_ PSIZE_T TotalSize
    )
{
    //
    // Check for multiplication overflow
    //
    if (ElementCount != 0 && ElementSize > (SIZE_T)(-1) / ElementCount) {
        *TotalSize = 0;
        return FALSE;
    }

    *TotalSize = ElementSize * ElementCount;
    return TRUE;
}

/**
 * @brief Add sizes with overflow check.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeSafeAdd(
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

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_MEMORY_UTILS_H_
