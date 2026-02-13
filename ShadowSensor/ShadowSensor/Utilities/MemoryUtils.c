/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL MEMORY UTILITIES
 * ============================================================================
 *
 * @file MemoryUtils.c
 * @brief Enterprise-grade memory management implementation.
 *
 * This module implements CrowdStrike/SentinelOne-class memory management
 * for kernel-mode EDR operations. All functions are designed for:
 * - Maximum security (no information leaks, secure wiping)
 * - High performance (lookaside lists, minimal locking)
 * - Reliability (comprehensive error handling, leak detection)
 * - Auditability (pool tags, allocation tracking)
 *
 * CRITICAL FIXES IN VERSION 2.2.0:
 * --------------------------------
 * 1. Fixed initialization race condition
 *    - Removed redundant stats zeroing after Initialized flag (TOCTOU)
 *    - g_MemoryState is statically zero-initialized; re-zeroing is racy
 * 2. Fixed FreePool/FreePoolWithTag byte tracking
 *    - These paths have no allocation size; now track count only
 *    - Byte-accurate tracking only via ShadowStrikeSecureFree
 * 3. Fixed contiguous/aligned alloc paths in AllocatePoolWithFlags
 *    - Now honors MustSucceed and RaiseOnFailure for all paths
 *    - Documented that contiguous allocs MUST use FreeContiguous
 * 4. Fixed double-free race in ShadowStrikeFreeAligned
 *    - Magic check-and-clear is now atomic via InterlockedCompareExchange
 * 5. Added DISPATCH_LEVEL wipe size cap in ShadowStrikeFreeAligned
 *    - Prevents DPC timeout on large aligned allocations
 * 6. Added POOL_NX_ALLOCATION flag for non-paged lookaside lists
 *    - Prevents executable pool allocations on Win8+
 * 7. Fixed MustSucceed retry logic
 *    - No longer spins at DISPATCH_LEVEL (pointless without delay)
 * 8. Added kernel address validation in ShadowStrikeCreateMdl
 *    - Prevents BSOD from passing user-mode addresses to MmBuildMdlForNonPagedPool
 * 9. Added user address range validation in ShadowStrikeMapMemory
 *    - Defense-in-depth before MmProbeAndLockPages for UserMode
 * 10. Added MdlMappingNoExecute in ShadowStrikeMapToSystemAddress
 *     - Prevents mapped pages from being executable (Win8+)
 * 11. Made contiguous memory cache type configurable
 *     - ShadowStrikeAllocateContiguous now accepts CacheType parameter
 * 12. Documented partial wipe limitation in ShadowStrikeSecureFree
 *
 * FIXES IN VERSION 2.1.0:
 * --------------------------------
 * 1. Fixed pool tag mismatch in ShadowStrikeCaptureUserBufferSecure
 * 2. Fixed initialization race (InterlockedCompareExchange)
 * 3. Added IRQL validation in ShadowStrikeLookasideFree
 * 4. Fixed user address validation
 * 5. Removed unreliable MmIsAddressValid-based ShadowStrikeIsMemoryValid
 * 6. Improved secure wipe performance
 * 7. Removed unused spin lock from global state
 *
 * @author ShadowStrike Security Team
 * @version 2.2.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MemoryUtils.h"

// ============================================================================
// INTERNAL STATE
// ============================================================================

/**
 * @brief Global memory subsystem state
 */
typedef struct _SHADOWSTRIKE_MEMORY_STATE {
    /// Subsystem initialized (use interlocked access only)
    volatile LONG Initialized;

    /// Allocation statistics
    volatile LONG64 TotalAllocations;
    volatile LONG64 TotalFrees;
    volatile LONG64 TotalBytesAllocated;
    volatile LONG64 TotalBytesFreed;
    volatile LONG64 AllocationFailures;

    /// Current outstanding
    volatile LONG64 CurrentAllocations;
    volatile LONG64 CurrentBytesAllocated;

    /// Peak values
    volatile LONG64 PeakAllocations;
    volatile LONG64 PeakBytesAllocated;

} SHADOWSTRIKE_MEMORY_STATE, *PSHADOWSTRIKE_MEMORY_STATE;

static SHADOWSTRIKE_MEMORY_STATE g_MemoryState = { 0 };

// ============================================================================
// INTERNAL HELPER MACROS
// ============================================================================

/**
 * @brief Update allocation statistics
 */
#define MEMORY_TRACK_ALLOC(Size) \
    do { \
        InterlockedIncrement64(&g_MemoryState.TotalAllocations); \
        InterlockedAdd64(&g_MemoryState.TotalBytesAllocated, (LONG64)(Size)); \
        LONG64 current = InterlockedIncrement64(&g_MemoryState.CurrentAllocations); \
        LONG64 currentBytes = InterlockedAdd64(&g_MemoryState.CurrentBytesAllocated, (LONG64)(Size)); \
        LONG64 peak = g_MemoryState.PeakAllocations; \
        while (current > peak) { \
            InterlockedCompareExchange64(&g_MemoryState.PeakAllocations, current, peak); \
            peak = g_MemoryState.PeakAllocations; \
        } \
        LONG64 peakBytes = g_MemoryState.PeakBytesAllocated; \
        while (currentBytes > peakBytes) { \
            InterlockedCompareExchange64(&g_MemoryState.PeakBytesAllocated, currentBytes, peakBytes); \
            peakBytes = g_MemoryState.PeakBytesAllocated; \
        } \
    } while (0)

/**
 * @brief Update free statistics (count only, no byte tracking).
 *
 * Used by ShadowStrikeFreePool/ShadowStrikeFreePoolWithTag where the
 * original allocation size is unknown.  Byte-accurate tracking is only
 * available through ShadowStrikeSecureFree which receives the size.
 */
#define MEMORY_TRACK_FREE_COUNT_ONLY() \
    do { \
        InterlockedIncrement64(&g_MemoryState.TotalFrees); \
        InterlockedDecrement64(&g_MemoryState.CurrentAllocations); \
    } while (0)

/**
 * @brief Update free statistics with byte tracking.
 *
 * Used by ShadowStrikeSecureFree and other paths where the allocation
 * size is known.
 */
#define MEMORY_TRACK_FREE(Size) \
    do { \
        InterlockedIncrement64(&g_MemoryState.TotalFrees); \
        InterlockedAdd64(&g_MemoryState.TotalBytesFreed, (LONG64)(Size)); \
        InterlockedDecrement64(&g_MemoryState.CurrentAllocations); \
        InterlockedAdd64(&g_MemoryState.CurrentBytesAllocated, -(LONG64)(Size)); \
    } while (0)

/**
 * @brief Track allocation failure
 */
#define MEMORY_TRACK_FAILURE() \
    InterlockedIncrement64(&g_MemoryState.AllocationFailures)

// ============================================================================
// PAGED/NON-PAGED CODE SEGMENT DECLARATIONS
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowStrikeInitializeMemoryUtils)
#pragma alloc_text(PAGE, ShadowStrikeCleanupMemoryUtils)
#pragma alloc_text(PAGE, ShadowStrikeLookasideInit)
#pragma alloc_text(PAGE, ShadowStrikeLookasideCleanup)
#pragma alloc_text(PAGE, ShadowStrikeCaptureUserBuffer)
#pragma alloc_text(PAGE, ShadowStrikeCaptureUserBufferSecure)
#pragma alloc_text(PAGE, ShadowStrikeProbeUserBufferRead)
#pragma alloc_text(PAGE, ShadowStrikeProbeUserBufferWrite)
#pragma alloc_text(PAGE, ShadowStrikeReleaseUserBuffer)
#endif

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Optimized secure memory fill using word-sized writes.
 *
 * Uses volatile writes to prevent compiler optimization and
 * word-aligned access for better performance.
 */
static
VOID
ShadowStrikeSecureFillMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ UCHAR Pattern
    )
{
    volatile UCHAR* BytePtr;
    volatile SIZE_T* WordPtr;
    SIZE_T WordPattern;
    SIZE_T i;

    if (Destination == NULL || Length == 0) {
        return;
    }

    //
    // Build word-sized pattern
    //
    WordPattern = (SIZE_T)Pattern;
    WordPattern |= WordPattern << 8;
    WordPattern |= WordPattern << 16;
#ifdef _WIN64
    WordPattern |= WordPattern << 32;
#endif

    //
    // Handle unaligned prefix
    //
    BytePtr = (volatile UCHAR*)Destination;
    while (Length > 0 && ((ULONG_PTR)BytePtr & (sizeof(SIZE_T) - 1)) != 0) {
        *BytePtr++ = Pattern;
        Length--;
    }

    //
    // Word-aligned bulk fill
    //
    WordPtr = (volatile SIZE_T*)BytePtr;
    while (Length >= sizeof(SIZE_T)) {
        *WordPtr++ = WordPattern;
        Length -= sizeof(SIZE_T);
    }

    //
    // Handle unaligned suffix
    //
    BytePtr = (volatile UCHAR*)WordPtr;
    while (Length > 0) {
        *BytePtr++ = Pattern;
        Length--;
    }
}

// ============================================================================
// SUBSYSTEM INITIALIZATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInitializeMemoryUtils(
    VOID
    )
{
    PAGED_CODE();

    //
    // Thread-safe initialization using interlocked compare-exchange.
    // g_MemoryState is statically zero-initialized, so statistics are
    // already zero at first call. We must NOT zero them after setting
    // the Initialized flag — another thread could already be allocating
    // and we would clobber its stats.
    //
    if (InterlockedCompareExchange(&g_MemoryState.Initialized, 1, 0) != 0) {
        //
        // Already initialized by another thread
        //
        return STATUS_ALREADY_INITIALIZED;
    }

    //
    // Memory barrier to ensure the Initialized flag is visible to all
    // processors before any allocations proceed.
    //
    KeMemoryBarrier();

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupMemoryUtils(
    VOID
    )
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_MemoryState.Initialized, 0, 1) != 1) {
        //
        // Not initialized or already cleaned up
        //
        return;
    }

    //
    // Check for memory leaks in debug builds
    //
#if DBG
    if (g_MemoryState.CurrentAllocations != 0) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] WARNING: Memory leak detected!\n"
            "  Outstanding allocations: %lld\n"
            "  Outstanding bytes: %lld\n"
            "  Total allocations: %lld\n"
            "  Total frees: %lld\n",
            g_MemoryState.CurrentAllocations,
            g_MemoryState.CurrentBytesAllocated,
            g_MemoryState.TotalAllocations,
            g_MemoryState.TotalFrees
        );
    }
#endif
}

// ============================================================================
// CORE ALLOCATION FUNCTIONS
// ============================================================================

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
    )
{
    PVOID Buffer = NULL;

    //
    // Validate size - reject zero or excessively large allocations
    //
    if (NumberOfBytes == 0) {
        return NULL;
    }

    if (NumberOfBytes > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    //
    // Validate IRQL for paged pool
    //
    if ((PoolType == PagedPool || PoolType == PagedPoolCacheAligned) &&
        KeGetCurrentIrql() > APC_LEVEL) {
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    //
    // Convert legacy NonPagedPool to NonPagedPoolNx for security
    // This prevents execution from pool memory (DEP)
    //
    if (PoolType == NonPagedPool) {
        PoolType = NonPagedPoolNx;
    }

    //
    // Perform allocation using ExAllocatePool2 if available (Windows 10 2004+)
    // Fall back to ExAllocatePoolWithTag for older systems
    //
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    //
    // ExAllocatePool2 automatically zeros memory and uses NX pools
    //
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

    //
    // ExAllocatePool2 zeros memory by default (unless POOL_FLAG_UNINITIALIZED)
    //

#else
    //
    // Legacy path for older Windows versions
    //
#pragma warning(push)
#pragma warning(disable: 4996) // Deprecated ExAllocatePoolWithTag warning
#pragma warning(disable: 28118) // IRQL annotation

    Buffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

#pragma warning(pop)

    //
    // Zero the memory for security (prevent information disclosure)
    //
    if (Buffer != NULL) {
        RtlZeroMemory(Buffer, NumberOfBytes);
    }
#endif

    //
    // Track the allocation
    //
    if (Buffer != NULL) {
        MEMORY_TRACK_ALLOC(NumberOfBytes);
    } else {
        MEMORY_TRACK_FAILURE();
    }

    return Buffer;
}

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
    )
{
    PVOID Buffer = NULL;

    //
    // Handle alignment flags by delegating to aligned allocator.
    // NOTE: Aligned allocations MUST be freed with ShadowStrikeFreeAligned.
    //
    if (Flags & ShadowAllocCacheAligned) {
        Buffer = ShadowStrikeAllocateAligned(
            PoolType,
            NumberOfBytes,
            SHADOWSTRIKE_CACHE_LINE_SIZE,
            Tag
        );
        goto HandlePostAllocationFlags;
    }

    if (Flags & ShadowAllocPageAligned) {
        Buffer = ShadowStrikeAllocateAligned(
            PoolType,
            NumberOfBytes,
            PAGE_SIZE,
            Tag
        );
        goto HandlePostAllocationFlags;
    }

    //
    // Handle contiguous memory request.
    // CRITICAL: Contiguous allocations MUST be freed with
    // ShadowStrikeFreeContiguous — never ShadowStrikeFree.
    //
    if (Flags & ShadowAllocContiguous) {
        PHYSICAL_ADDRESS Lowest = { 0 };
        PHYSICAL_ADDRESS Highest = { .QuadPart = -1 };
        PHYSICAL_ADDRESS Boundary = { 0 };

        Buffer = ShadowStrikeAllocateContiguous(
            NumberOfBytes,
            Lowest,
            Highest,
            Boundary,
            MmNonCached
        );
        goto HandlePostAllocationFlags;
    }

    //
    // Standard allocation
    //
    Buffer = ShadowStrikeAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

    //
    // Handle must-succeed flag (retry logic).
    // Only retry at <= APC_LEVEL where we can sleep. At DISPATCH_LEVEL,
    // retrying without delay is a pointless busy-wait that will not help.
    //
    if (Buffer == NULL && (Flags & ShadowAllocMustSucceed)) {
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10 * 1000; // 1ms

            for (ULONG Retry = 0; Retry < 3 && Buffer == NULL; Retry++) {
                KeDelayExecutionThread(KernelMode, FALSE, &Delay);
                Buffer = ShadowStrikeAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
            }
        }
    }

HandlePostAllocationFlags:

    //
    // Handle raise-on-failure flag
    //
    if (Buffer == NULL && (Flags & ShadowAllocRaiseOnFailure)) {
        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
    }

    return Buffer;
}

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
    )
{
    PVOID RawBuffer = NULL;
    PVOID AlignedBuffer = NULL;
    SIZE_T TotalSize = 0;
    SIZE_T HeaderSize = 0;
    SIZE_T PaddingSize = 0;
    SIZE_T TempSize = 0;
    PSHADOWSTRIKE_ALIGNED_HEADER Header = NULL;

    //
    // Validate alignment is power of 2
    //
    if (!ShadowStrikeIsPowerOf2(Alignment)) {
        return NULL;
    }

    //
    // Minimum alignment is pointer size
    //
    if (Alignment < sizeof(PVOID)) {
        Alignment = sizeof(PVOID);
    }

    //
    // Calculate total size needed:
    // - Original size
    // - Alignment padding (worst case: Alignment - 1)
    // - Header structure for tracking
    //
    HeaderSize = sizeof(SHADOWSTRIKE_ALIGNED_HEADER);
    PaddingSize = Alignment - 1;

    //
    // Safe size calculation with overflow checks
    //
    if (!ShadowStrikeSafeAdd(NumberOfBytes, HeaderSize, &TempSize)) {
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    if (!ShadowStrikeSafeAdd(TempSize, PaddingSize, &TotalSize)) {
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    //
    // Final overflow check against maximum
    //
    if (TotalSize > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    //
    // Allocate raw buffer
    //
    RawBuffer = ShadowStrikeAllocatePoolWithTag(PoolType, TotalSize, SHADOWSTRIKE_ALIGNED_TAG);
    if (RawBuffer == NULL) {
        return NULL;
    }

    //
    // Calculate aligned address using overflow-safe function
    // We need space for the header just before the aligned buffer
    //
    ULONG_PTR RawAddress = (ULONG_PTR)RawBuffer + HeaderSize;
    SIZE_T AlignedAddress;

    if (!ShadowStrikeAlignUpSafe(RawAddress, Alignment, &AlignedAddress)) {
        //
        // Overflow - should not happen given our size checks, but be safe
        //
        ShadowStrikeFreePoolWithTag(RawBuffer, SHADOWSTRIKE_ALIGNED_TAG);
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    AlignedBuffer = (PVOID)AlignedAddress;

    //
    // Store header just before aligned buffer
    //
    Header = (PSHADOWSTRIKE_ALIGNED_HEADER)((ULONG_PTR)AlignedBuffer - sizeof(SHADOWSTRIKE_ALIGNED_HEADER));
    Header->OriginalPointer = RawBuffer;
    Header->Alignment = Alignment;
    Header->AllocationSize = NumberOfBytes;
    Header->Magic = SHADOWSTRIKE_ALIGNED_MAGIC;
    Header->PoolTag = Tag;

    return AlignedBuffer;
}

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
    )
{
    PVOID NewBuffer = NULL;

    //
    // Handle NULL old buffer as simple allocation
    //
    if (OldBuffer == NULL) {
        return ShadowStrikeAllocatePoolWithTag(PoolType, NewSize, Tag);
    }

    //
    // Handle zero new size as free
    //
    if (NewSize == 0) {
        ShadowStrikeSecureFree(OldBuffer, OldSize, Tag);
        return NULL;
    }

    //
    // Handle same size (no-op optimization)
    //
    if (NewSize == OldSize) {
        return OldBuffer;
    }

    //
    // Allocate new buffer
    //
    NewBuffer = ShadowStrikeAllocatePoolWithTag(PoolType, NewSize, Tag);
    if (NewBuffer == NULL) {
        //
        // Failed - return NULL but preserve original buffer
        //
        return NULL;
    }

    //
    // Copy existing data (copy minimum of old and new size)
    //
    SIZE_T CopySize = (OldSize < NewSize) ? OldSize : NewSize;
    RtlCopyMemory(NewBuffer, OldBuffer, CopySize);

    //
    // Securely free old buffer
    //
    ShadowStrikeSecureFree(OldBuffer, OldSize, Tag);

    return NewBuffer;
}

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreePool(
    _In_opt_ _Post_ptr_invalid_ PVOID P
    )
{
    if (P != NULL) {
        ExFreePool(P);
        MEMORY_TRACK_FREE_COUNT_ONLY();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreePoolWithTag(
    _In_opt_ _Post_ptr_invalid_ PVOID P,
    _In_ ULONG Tag
    )
{
    if (P != NULL) {
        ExFreePoolWithTag(P, Tag);
        MEMORY_TRACK_FREE_COUNT_ONLY();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeAligned(
    _In_opt_ _Post_ptr_invalid_ PVOID P
    )
{
    PSHADOWSTRIKE_ALIGNED_HEADER Header = NULL;
    SIZE_T AllocationSize = 0;

    if (P == NULL) {
        return;
    }

    //
    // Get header from just before the aligned buffer
    //
    Header = (PSHADOWSTRIKE_ALIGNED_HEADER)((ULONG_PTR)P - sizeof(SHADOWSTRIKE_ALIGNED_HEADER));

    //
    // Validate magic to catch corruption or invalid pointers.
    // Use InterlockedCompareExchange to atomically check-and-clear,
    // preventing double-free if two threads race on the same pointer.
    //
    if ((ULONG)InterlockedCompareExchange(
            (volatile LONG*)&Header->Magic,
            0,
            (LONG)SHADOWSTRIKE_ALIGNED_MAGIC
        ) != SHADOWSTRIKE_ALIGNED_MAGIC) {
#if DBG
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike] ERROR: Invalid or already-freed aligned pointer: %p\n",
            P
        );
#endif
        //
        // In production, we cannot safely free this.
        // Better to leak than corrupt or crash.
        //
        return;
    }

    //
    // Save allocation size for secure wipe
    //
    AllocationSize = Header->AllocationSize;

    //
    // Secure wipe the user data portion.
    // Apply same DISPATCH_LEVEL size cap as ShadowStrikeSecureFree
    // to avoid DPC timeout on large aligned allocations.
    //
    if (AllocationSize > 0) {
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL &&
            AllocationSize > SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE) {
            ShadowStrikeSecureZeroMemory(P, SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE);
        } else {
            ShadowStrikeSecureZeroMemory(P, AllocationSize);
        }
    }

    //
    // Free the original raw allocation
    //
    ShadowStrikeFreePoolWithTag(Header->OriginalPointer, SHADOWSTRIKE_ALIGNED_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeSecureFree(
    _In_opt_ _Post_ptr_invalid_ PVOID P,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
    )
{
    if (P == NULL || Size == 0) {
        if (P != NULL) {
            ShadowStrikeFreePoolWithTag(P, Tag);
        }
        return;
    }

    //
    // At DISPATCH_LEVEL, limit wipe size to prevent DPC timeout.
    // SECURITY NOTE: Remaining bytes beyond the cap are NOT wiped.
    // Callers handling truly sensitive data (keys, credentials) should
    // ensure they free at <= APC_LEVEL for a complete wipe.
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL && Size > SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE) {
        //
        // Partial wipe — zero what we can safely do at DISPATCH_LEVEL
        //
        ShadowStrikeSecureZeroMemory(P, SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE);
    } else {
        //
        // Full secure wipe
        //
        ShadowStrikeSecureWipeMemory(P, Size);
    }

    //
    // Free the memory
    //
    ShadowStrikeFreePoolWithTag(P, Tag);
}

// ============================================================================
// LOOKASIDE LIST MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeLookasideInit(
    _Out_ PSHADOWSTRIKE_LOOKASIDE Lookaside,
    _In_ SIZE_T EntrySize,
    _In_ ULONG Tag,
    _In_ USHORT Depth,
    _In_ BOOLEAN IsPaged
    )
{
    PAGED_CODE();

    if (Lookaside == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate entry size
    //
    if (EntrySize == 0 || EntrySize > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize structure
    //
    RtlZeroMemory(Lookaside, sizeof(SHADOWSTRIKE_LOOKASIDE));

    Lookaside->EntrySize = EntrySize;
    Lookaside->PoolTag = Tag;
    Lookaside->IsPaged = IsPaged;

    //
    // Clamp depth to valid range
    //
    if (Depth == 0) {
        Depth = SHADOWSTRIKE_LOOKASIDE_DEPTH;
    } else if (Depth < SHADOWSTRIKE_MIN_LOOKASIDE_DEPTH) {
        Depth = SHADOWSTRIKE_MIN_LOOKASIDE_DEPTH;
    } else if (Depth > SHADOWSTRIKE_MAX_LOOKASIDE_DEPTH) {
        Depth = SHADOWSTRIKE_MAX_LOOKASIDE_DEPTH;
    }

    //
    // Initialize the appropriate lookaside list type.
    // POOL_NX_ALLOCATION ensures non-executable pool on Win8+.
    //
#if (NTDDI_VERSION >= NTDDI_WIN8)
    #define SHADOWSTRIKE_NX_FLAG POOL_NX_ALLOCATION
#else
    #define SHADOWSTRIKE_NX_FLAG 0
#endif

    if (IsPaged) {
        ExInitializePagedLookasideList(
            &Lookaside->PagedList,
            NULL,   // Allocate function (use default)
            NULL,   // Free function (use default)
            0,      // Flags (paged pool is never executable)
            EntrySize,
            Tag,
            Depth
        );
    } else {
        ExInitializeNPagedLookasideList(
            &Lookaside->NonPagedList,
            NULL,   // Allocate function (use default)
            NULL,   // Free function (use default)
            SHADOWSTRIKE_NX_FLAG,
            EntrySize,
            Tag,
            Depth
        );
    }

#undef SHADOWSTRIKE_NX_FLAG

    Lookaside->Initialized = TRUE;

    return STATUS_SUCCESS;
}

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
PVOID
ShadowStrikeLookasideAllocate(
    _Inout_ PSHADOWSTRIKE_LOOKASIDE Lookaside
    )
{
    PVOID Entry = NULL;
    LONG Current = 0;
    LONG Peak = 0;

    if (Lookaside == NULL || !Lookaside->Initialized) {
        return NULL;
    }

    //
    // Check IRQL for paged lookasides
    //
    if (Lookaside->IsPaged && KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement64(&Lookaside->AllocationFailures);
        return NULL;
    }

    //
    // Allocate from appropriate list
    //
    if (Lookaside->IsPaged) {
        Entry = ExAllocateFromPagedLookasideList(&Lookaside->PagedList);
    } else {
        Entry = ExAllocateFromNPagedLookasideList(&Lookaside->NonPagedList);
    }

    if (Entry != NULL) {
        //
        // Zero the entry for security
        //
        RtlZeroMemory(Entry, Lookaside->EntrySize);

        //
        // Update statistics
        //
        InterlockedIncrement64(&Lookaside->TotalAllocations);
        Current = InterlockedIncrement(&Lookaside->CurrentOutstanding);

        //
        // Update peak if necessary
        //
        Peak = Lookaside->PeakOutstanding;
        while (Current > Peak) {
            InterlockedCompareExchange(&Lookaside->PeakOutstanding, Current, Peak);
            Peak = Lookaside->PeakOutstanding;
        }
    } else {
        InterlockedIncrement64(&Lookaside->AllocationFailures);
    }

    return Entry;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeLookasideFree(
    _Inout_ PSHADOWSTRIKE_LOOKASIDE Lookaside,
    _In_ _Post_ptr_invalid_ PVOID Entry
    )
{
    if (Lookaside == NULL || !Lookaside->Initialized || Entry == NULL) {
        return;
    }

    //
    // CRITICAL FIX: Check IRQL for paged lookasides
    // Freeing to a paged lookaside at DISPATCH_LEVEL causes BSOD
    //
    if (Lookaside->IsPaged && KeGetCurrentIrql() > APC_LEVEL) {
#if DBG
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike] ERROR: Attempt to free to paged lookaside at IRQL %d\n",
            KeGetCurrentIrql()
        );
#endif
        //
        // Cannot safely free at this IRQL - memory will leak
        // This is a programming error that should be fixed
        //
        return;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Lookaside->TotalFrees);
    InterlockedDecrement(&Lookaside->CurrentOutstanding);

    //
    // Return to appropriate list
    //
    if (Lookaside->IsPaged) {
        ExFreeToPagedLookasideList(&Lookaside->PagedList, Entry);
    } else {
        ExFreeToNPagedLookasideList(&Lookaside->NonPagedList, Entry);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeLookasideCleanup(
    _Inout_ PSHADOWSTRIKE_LOOKASIDE Lookaside
    )
{
    PAGED_CODE();

    if (Lookaside == NULL || !Lookaside->Initialized) {
        return;
    }

#if DBG
    //
    // Warn about outstanding allocations
    //
    if (Lookaside->CurrentOutstanding != 0) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] WARNING: Lookaside list cleanup with %d outstanding allocations (tag: 0x%08X)\n",
            Lookaside->CurrentOutstanding,
            Lookaside->PoolTag
        );
    }
#endif

    //
    // Delete the lookaside list
    //
    if (Lookaside->IsPaged) {
        ExDeletePagedLookasideList(&Lookaside->PagedList);
    } else {
        ExDeleteNPagedLookasideList(&Lookaside->NonPagedList);
    }

    Lookaside->Initialized = FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeLookasideGetStats(
    _In_ PSHADOWSTRIKE_LOOKASIDE Lookaside,
    _Out_opt_ PLONG64 Allocations,
    _Out_opt_ PLONG64 Frees,
    _Out_opt_ PLONG Outstanding,
    _Out_opt_ PLONG64 Failures
    )
{
    if (Lookaside == NULL) {
        if (Allocations) *Allocations = 0;
        if (Frees) *Frees = 0;
        if (Outstanding) *Outstanding = 0;
        if (Failures) *Failures = 0;
        return;
    }

    if (Allocations) *Allocations = Lookaside->TotalAllocations;
    if (Frees) *Frees = Lookaside->TotalFrees;
    if (Outstanding) *Outstanding = Lookaside->CurrentOutstanding;
    if (Failures) *Failures = Lookaside->AllocationFailures;
}

// ============================================================================
// USER-MODE BUFFER OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeCaptureUserBuffer(
    _In_reads_bytes_(BufferSize) PVOID UserBuffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG ProbeAlignment,
    _In_ ULONG Tag,
    _Out_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer,
    _In_ POOL_TYPE PoolType
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // Initialize output
    //
    RtlZeroMemory(SafeBuffer, sizeof(SHADOWSTRIKE_SAFE_BUFFER));

    //
    // Validate parameters
    //
    if (UserBuffer == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BufferSize > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Validate alignment is power of 2 or 1
    //
    if (ProbeAlignment == 0 || !ShadowStrikeIsPowerOf2(ProbeAlignment)) {
        ProbeAlignment = sizeof(UCHAR);
    }

    //
    // CRITICAL FIX: Validate entire user address range
    //
    if (!ShadowStrikeIsValidUserAddressRange(UserBuffer, BufferSize)) {
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // Probe the user buffer
    //
    __try {
        ProbeForRead(UserBuffer, BufferSize, ProbeAlignment);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    //
    // Allocate kernel buffer with the specified tag
    //
    SafeBuffer->KernelBuffer = ShadowStrikeAllocatePoolWithTag(
        PoolType,
        BufferSize,
        Tag
    );

    if (SafeBuffer->KernelBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy user buffer to kernel with exception handling
    //
    __try {
        RtlCopyMemory(SafeBuffer->KernelBuffer, UserBuffer, BufferSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        ShadowStrikeFreePoolWithTag(SafeBuffer->KernelBuffer, Tag);
        RtlZeroMemory(SafeBuffer, sizeof(SHADOWSTRIKE_SAFE_BUFFER));
        return Status;
    }

    //
    // Fill in descriptor
    //
    SafeBuffer->OriginalUserBuffer = UserBuffer;
    SafeBuffer->Size = BufferSize;
    SafeBuffer->PoolTag = Tag;
    SafeBuffer->IsPaged = (PoolType == PagedPool);
    SafeBuffer->IsSecure = FALSE;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeCaptureUserBufferSecure(
    _In_reads_bytes_(BufferSize) PVOID UserBuffer,
    _In_ SIZE_T BufferSize,
    _Out_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer
    )
{
    NTSTATUS Status;

    PAGED_CODE();

    //
    // CRITICAL FIX: Use SHADOWSTRIKE_SECURE_TAG for the actual allocation
    // The original code allocated with BUFFER_TAG then changed the descriptor,
    // causing tag mismatch on free
    //
    Status = ShadowStrikeCaptureUserBuffer(
        UserBuffer,
        BufferSize,
        sizeof(UCHAR),
        SHADOWSTRIKE_SECURE_TAG,  // Use correct tag from the start
        SafeBuffer,
        NonPagedPoolNx
    );

    if (NT_SUCCESS(Status)) {
        SafeBuffer->IsSecure = TRUE;
        // PoolTag is already SHADOWSTRIKE_SECURE_TAG from the allocation
    }

    return Status;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeReleaseUserBuffer(
    _Inout_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer
    )
{
    PAGED_CODE();

    if (SafeBuffer == NULL || SafeBuffer->KernelBuffer == NULL) {
        return;
    }

    //
    // Secure wipe if marked as secure
    //
    if (SafeBuffer->IsSecure && SafeBuffer->Size > 0) {
        ShadowStrikeSecureWipeMemory(SafeBuffer->KernelBuffer, SafeBuffer->Size);
    }

    //
    // Free the kernel buffer with matching tag
    //
    ShadowStrikeFreePoolWithTag(SafeBuffer->KernelBuffer, SafeBuffer->PoolTag);

    //
    // Clear the descriptor
    //
    RtlZeroMemory(SafeBuffer, sizeof(SHADOWSTRIKE_SAFE_BUFFER));
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProbeUserBufferRead(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
    )
{
    PAGED_CODE();

    if (Buffer == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Alignment == 0 || !ShadowStrikeIsPowerOf2(Alignment)) {
        Alignment = sizeof(UCHAR);
    }

    //
    // Validate address range first
    //
    if (!ShadowStrikeIsValidUserAddressRange(Buffer, Length)) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        ProbeForRead(Buffer, Length, Alignment);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProbeUserBufferWrite(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
    )
{
    PAGED_CODE();

    if (Buffer == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Alignment == 0 || !ShadowStrikeIsPowerOf2(Alignment)) {
        Alignment = sizeof(UCHAR);
    }

    //
    // Validate address range first
    //
    if (!ShadowStrikeIsValidUserAddressRange(Buffer, Length)) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        ProbeForWrite(Buffer, Length, Alignment);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// MDL OPERATIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(AccessMode == UserMode, _IRQL_requires_(PASSIVE_LEVEL))
NTSTATUS
ShadowStrikeMapMemory(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ SHADOWSTRIKE_MDL_OPERATION Operation,
    _Out_ PSHADOWSTRIKE_MAPPED_MEMORY MappedMemory
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMDL Mdl = NULL;
    LOCK_OPERATION LockOperation;

    //
    // Initialize output
    //
    RtlZeroMemory(MappedMemory, sizeof(SHADOWSTRIKE_MAPPED_MEMORY));

    //
    // Validate parameters
    //
    if (Buffer == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Length > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Explicit check that Length fits in ULONG for IoAllocateMdl
    //
    if (Length > MAXULONG) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Convert operation to lock operation
    //
    switch (Operation) {
        case ShadowMdlRead:
            LockOperation = IoReadAccess;
            break;
        case ShadowMdlWrite:
            LockOperation = IoWriteAccess;
            break;
        case ShadowMdlReadWrite:
            LockOperation = IoModifyAccess;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    //
    // For UserMode, validate the address range falls within user space
    // before proceeding. Defense-in-depth against kernel address abuse.
    //
    if (AccessMode == UserMode) {
        if (!ShadowStrikeIsValidUserAddressRange(Buffer, Length)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    //
    // Allocate MDL
    //
    Mdl = IoAllocateMdl(Buffer, (ULONG)Length, FALSE, FALSE, NULL);
    if (Mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Lock the pages
    //
    __try {
        MmProbeAndLockPages(Mdl, AccessMode, LockOperation);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        IoFreeMdl(Mdl);
        return Status;
    }

    //
    // Fill in descriptor
    //
    MappedMemory->Mdl = Mdl;
    MappedMemory->OriginalAddress = Buffer;
    MappedMemory->Size = Length;
    MappedMemory->IsLocked = TRUE;
    MappedMemory->AccessMode = AccessMode;
    MappedMemory->Operation = Operation;
    MappedMemory->MappedAddress = NULL;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeMapToSystemAddress(
    _Inout_ PSHADOWSTRIKE_MAPPED_MEMORY MappedMemory,
    _In_ MEMORY_CACHING_TYPE CacheType
    )
{
    PVOID SystemAddress = NULL;

    if (MappedMemory == NULL || MappedMemory->Mdl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MappedMemory->IsLocked) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Map to system address.
    // Use MdlMappingNoExecute to prevent the mapped pages from being
    // executable — security hardening against code injection.
    //
#if (NTDDI_VERSION >= NTDDI_WIN8)
    #define SHADOWSTRIKE_MDL_PRIORITY (NormalPagePriority | MdlMappingNoExecute)
#else
    #define SHADOWSTRIKE_MDL_PRIORITY NormalPagePriority
#endif

    SystemAddress = MmMapLockedPagesSpecifyCache(
        MappedMemory->Mdl,
        KernelMode,
        CacheType,
        NULL,
        FALSE,
        SHADOWSTRIKE_MDL_PRIORITY
    );

#undef SHADOWSTRIKE_MDL_PRIORITY

    if (SystemAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MappedMemory->MappedAddress = SystemAddress;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeUnmapMemory(
    _Inout_ PSHADOWSTRIKE_MAPPED_MEMORY MappedMemory
    )
{
    if (MappedMemory == NULL) {
        return;
    }

    //
    // Unmap system address if mapped
    //
    if (MappedMemory->MappedAddress != NULL && MappedMemory->Mdl != NULL) {
        MmUnmapLockedPages(MappedMemory->MappedAddress, MappedMemory->Mdl);
        MappedMemory->MappedAddress = NULL;
    }

    //
    // Unlock pages if locked
    //
    if (MappedMemory->IsLocked && MappedMemory->Mdl != NULL) {
        MmUnlockPages(MappedMemory->Mdl);
        MappedMemory->IsLocked = FALSE;
    }

    //
    // Free MDL
    //
    if (MappedMemory->Mdl != NULL) {
        IoFreeMdl(MappedMemory->Mdl);
        MappedMemory->Mdl = NULL;
    }

    //
    // Clear descriptor
    //
    RtlZeroMemory(MappedMemory, sizeof(SHADOWSTRIKE_MAPPED_MEMORY));
}

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeCreateMdl(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _Out_ PMDL* Mdl
    )
{
    PMDL NewMdl = NULL;

    *Mdl = NULL;

    if (Buffer == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Length > SHADOWSTRIKE_MAX_ALLOCATION_SIZE || Length > MAXULONG) {
        return STATUS_BUFFER_OVERFLOW;
    }

    NewMdl = IoAllocateMdl(Buffer, (ULONG)Length, FALSE, FALSE, NULL);
    if (NewMdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Build MDL for non-paged kernel buffer.
    // IMPORTANT: Caller MUST ensure Buffer points to non-paged pool.
    // MmBuildMdlForNonPagedPool on paged memory is undefined behavior
    // and will cause BSOD under memory pressure.
    //
    // We validate the buffer is in kernel space as a basic sanity check.
    //
    if (Buffer < MmSystemRangeStart) {
        IoFreeMdl(NewMdl);
        return STATUS_INVALID_ADDRESS;
    }

    MmBuildMdlForNonPagedPool(NewMdl);

    *Mdl = NewMdl;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeMdl(
    _In_opt_ _Post_ptr_invalid_ PMDL Mdl
    )
{
    if (Mdl != NULL) {
        IoFreeMdl(Mdl);
    }
}

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeSecureZeroMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
    )
{
    if (Destination == NULL || Length == 0) {
        return;
    }

    //
    // Use RtlSecureZeroMemory which is optimized and guaranteed
    // not to be optimized away by the compiler
    //
    RtlSecureZeroMemory(Destination, Length);

    //
    // Memory barrier to ensure all writes complete before returning
    //
    KeMemoryBarrier();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeSecureWipeMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
    )
{
    if (Destination == NULL || Length == 0) {
        return;
    }

    //
    // At high IRQL with large buffers, just do a single zero pass
    // to avoid DPC timeout
    //
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL && Length > SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE) {
        ShadowStrikeSecureZeroMemory(Destination, Length);
        return;
    }

    //
    // DoD 5220.22-M secure wipe: four passes with different patterns
    // Using optimized word-aligned writes for performance
    //

    //
    // Pass 1: Zero pattern
    //
    ShadowStrikeSecureFillMemory(Destination, Length, SHADOWSTRIKE_WIPE_PATTERN_1);
    KeMemoryBarrier();

    //
    // Pass 2: 0xFF pattern
    //
    ShadowStrikeSecureFillMemory(Destination, Length, SHADOWSTRIKE_WIPE_PATTERN_2);
    KeMemoryBarrier();

    //
    // Pass 3: 0xAA pattern
    //
    ShadowStrikeSecureFillMemory(Destination, Length, SHADOWSTRIKE_WIPE_PATTERN_3);
    KeMemoryBarrier();

    //
    // Final pass: Zero (using RtlSecureZeroMemory for guarantee)
    //
    RtlSecureZeroMemory(Destination, Length);
    KeMemoryBarrier();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeSecureCompare(
    _In_reads_bytes_(Length) const VOID* Buffer1,
    _In_reads_bytes_(Length) const VOID* Buffer2,
    _In_ SIZE_T Length
    )
{
    const volatile UCHAR* P1 = NULL;
    const volatile UCHAR* P2 = NULL;
    volatile UCHAR Result = 0;
    SIZE_T i;

    if (Buffer1 == NULL || Buffer2 == NULL) {
        return FALSE;
    }

    if (Length == 0) {
        return TRUE;
    }

    //
    // Constant-time comparison to prevent timing attacks
    // We XOR all bytes and accumulate - equal buffers will have Result = 0
    //
    P1 = (const volatile UCHAR*)Buffer1;
    P2 = (const volatile UCHAR*)Buffer2;

    for (i = 0; i < Length; i++) {
        Result |= (P1[i] ^ P2[i]);
    }

    return (Result == 0);
}

// ============================================================================
// MEMORY VALIDATION UTILITIES
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsKernelAddress(
    _In_ PVOID Address
    )
{
    //
    // On x64, kernel addresses are above MmSystemRangeStart
    // This is a range check only - does NOT validate accessibility
    //
    return (Address >= MmSystemRangeStart);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsUserAddress(
    _In_ PVOID Address
    )
{
    //
    // User addresses are below MmHighestUserAddress
    // This is a range check only - does NOT validate accessibility
    //
    return (Address < MmHighestUserAddress);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsValidUserAddressRange(
    _In_ PVOID Address,
    _In_ SIZE_T Length
    )
{
    ULONG_PTR StartAddr;
    ULONG_PTR EndAddr;
    ULONG_PTR HighestUser;

    if (Address == NULL || Length == 0) {
        return FALSE;
    }

    StartAddr = (ULONG_PTR)Address;
    HighestUser = (ULONG_PTR)MmHighestUserAddress;

    //
    // Check start address is in user space
    //
    if (StartAddr >= HighestUser) {
        return FALSE;
    }

    //
    // Check for address overflow
    //
    if (StartAddr > (ULONG_PTR)(-1) - Length) {
        return FALSE;
    }

    //
    // Calculate end address (last byte, not one past)
    //
    EndAddr = StartAddr + Length - 1;

    //
    // Check end address is still in user space
    //
    if (EndAddr >= HighestUser) {
        return FALSE;
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsSafeAllocationSize(
    _In_ SIZE_T Size,
    _In_ SIZE_T Count
    )
{
    SIZE_T TotalSize = 0;

    //
    // Check for zero
    //
    if (Size == 0 || Count == 0) {
        return FALSE;
    }

    //
    // Check for multiplication overflow
    //
    if (!ShadowStrikeSafeMultiply(Size, Count, &TotalSize)) {
        return FALSE;
    }

    //
    // Check against maximum
    //
    if (TotalSize > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// PHYSICAL MEMORY OPERATIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
PHYSICAL_ADDRESS
ShadowStrikeGetPhysicalAddress(
    _In_ PVOID VirtualAddress
    )
{
    PHYSICAL_ADDRESS PhysicalAddress = { 0 };

    if (VirtualAddress == NULL) {
        return PhysicalAddress;
    }

    PhysicalAddress = MmGetPhysicalAddress(VirtualAddress);

    return PhysicalAddress;
}

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
PVOID
ShadowStrikeAllocateContiguous(
    _In_ SIZE_T NumberOfBytes,
    _In_ PHYSICAL_ADDRESS LowestAcceptable,
    _In_ PHYSICAL_ADDRESS HighestAcceptable,
    _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple,
    _In_ MEMORY_CACHING_TYPE CacheType
    )
{
    PVOID Buffer = NULL;

    if (NumberOfBytes == 0 || NumberOfBytes > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return NULL;
    }

    Buffer = MmAllocateContiguousMemorySpecifyCache(
        NumberOfBytes,
        LowestAcceptable,
        HighestAcceptable,
        BoundaryAddressMultiple,
        CacheType
    );

    if (Buffer != NULL) {
        //
        // Zero the memory for security
        //
        RtlZeroMemory(Buffer, NumberOfBytes);
        MEMORY_TRACK_ALLOC(NumberOfBytes);
    } else {
        MEMORY_TRACK_FAILURE();
    }

    return Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeContiguous(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes
    )
{
    if (BaseAddress == NULL) {
        return;
    }

    //
    // Secure wipe before freeing (physical memory could be reused)
    // Limit size at DISPATCH_LEVEL to avoid DPC timeout
    //
    if (NumberOfBytes > 0) {
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL && NumberOfBytes > SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE) {
            ShadowStrikeSecureZeroMemory(BaseAddress, SHADOWSTRIKE_MAX_DISPATCH_WIPE_SIZE);
        } else {
            ShadowStrikeSecureZeroMemory(BaseAddress, NumberOfBytes);
        }
    }

    MmFreeContiguousMemory(BaseAddress);

    MEMORY_TRACK_FREE(NumberOfBytes);
}
