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
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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
    /// Subsystem initialized
    BOOLEAN Initialized;

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

    /// Lock for statistics update (only for peak calculation)
    KSPIN_LOCK StatsLock;

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
        LONG64 peak = g_MemoryState.PeakAllocations; \
        while (current > peak) { \
            InterlockedCompareExchange64(&g_MemoryState.PeakAllocations, current, peak); \
            peak = g_MemoryState.PeakAllocations; \
        } \
    } while (0)

/**
 * @brief Update free statistics
 */
#define MEMORY_TRACK_FREE(Size) \
    do { \
        InterlockedIncrement64(&g_MemoryState.TotalFrees); \
        InterlockedAdd64(&g_MemoryState.TotalBytesFreed, (LONG64)(Size)); \
        InterlockedDecrement64(&g_MemoryState.CurrentAllocations); \
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
#endif

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
    // Prevent double initialization
    //
    if (g_MemoryState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    //
    // Zero the state structure
    //
    RtlZeroMemory(&g_MemoryState, sizeof(g_MemoryState));

    //
    // Initialize spin lock for statistics
    //
    KeInitializeSpinLock(&g_MemoryState.StatsLock);

    //
    // Mark as initialized
    //
    g_MemoryState.Initialized = TRUE;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupMemoryUtils(
    VOID
    )
{
    PAGED_CODE();

    if (!g_MemoryState.Initialized) {
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
            "[ShadowStrike] WARNING: Memory leak detected! Outstanding allocations: %lld\n",
            g_MemoryState.CurrentAllocations
        );
    }
#endif

    g_MemoryState.Initialized = FALSE;
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
    POOL_FLAGS PoolFlags = POOL_FLAG_UNINITIALIZED;

    if (PoolType == PagedPool || PoolType == PagedPoolCacheAligned) {
        PoolFlags = POOL_FLAG_PAGED;
    } else {
        PoolFlags = POOL_FLAG_NON_PAGED;
    }

    if (PoolType == NonPagedPoolCacheAligned || PoolType == PagedPoolCacheAligned) {
        PoolFlags |= POOL_FLAG_CACHE_ALIGNED;
    }

    Buffer = ExAllocatePool2(PoolFlags, NumberOfBytes, Tag);

    if (Buffer != NULL) {
        //
        // ExAllocatePool2 with POOL_FLAG_UNINITIALIZED doesn't zero
        // We want zeroed memory for security, so zero it
        //
        RtlZeroMemory(Buffer, NumberOfBytes);
    }

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
    // Handle alignment flags by delegating to aligned allocator
    //
    if (Flags & ShadowAllocCacheAligned) {
        return ShadowStrikeAllocateAligned(
            PoolType,
            NumberOfBytes,
            SHADOWSTRIKE_CACHE_LINE_SIZE,
            Tag
        );
    }

    if (Flags & ShadowAllocPageAligned) {
        return ShadowStrikeAllocateAligned(
            PoolType,
            NumberOfBytes,
            PAGE_SIZE,
            Tag
        );
    }

    //
    // Handle contiguous memory request
    //
    if (Flags & ShadowAllocContiguous) {
        PHYSICAL_ADDRESS Lowest = { 0 };
        PHYSICAL_ADDRESS Highest = { .QuadPart = -1 };
        PHYSICAL_ADDRESS Boundary = { 0 };

        return ShadowStrikeAllocateContiguous(
            NumberOfBytes,
            Lowest,
            Highest,
            Boundary
        );
    }

    //
    // Standard allocation
    //
    Buffer = ShadowStrikeAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

    //
    // Handle must-succeed flag (retry logic)
    //
    if (Buffer == NULL && (Flags & ShadowAllocMustSucceed)) {
        //
        // Brief delay and retry for transient failures
        // This is a last-resort measure for critical allocations
        //
        LARGE_INTEGER Delay;
        Delay.QuadPart = -10 * 1000; // 1ms

        for (ULONG Retry = 0; Retry < 3 && Buffer == NULL; Retry++) {
            if (KeGetCurrentIrql() <= APC_LEVEL) {
                KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            }
            Buffer = ShadowStrikeAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
        }
    }

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
    SIZE_T HeaderSize = sizeof(SHADOWSTRIKE_ALIGNED_HEADER);
    SIZE_T PaddingSize = Alignment - 1;

    //
    // Safe size calculation with overflow checks
    //
    if (!ShadowStrikeSafeAdd(NumberOfBytes, HeaderSize, &TotalSize)) {
        MEMORY_TRACK_FAILURE();
        return NULL;
    }

    if (!ShadowStrikeSafeAdd(TotalSize, PaddingSize, &TotalSize)) {
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
    // Calculate aligned address
    // We need space for the header just before the aligned buffer
    //
    ULONG_PTR RawAddress = (ULONG_PTR)RawBuffer + HeaderSize;
    ULONG_PTR AlignedAddress = ShadowStrikeAlignUp(RawAddress, Alignment);

    AlignedBuffer = (PVOID)AlignedAddress;

    //
    // Store header just before aligned buffer
    //
    Header = (PSHADOWSTRIKE_ALIGNED_HEADER)((ULONG_PTR)AlignedBuffer - sizeof(SHADOWSTRIKE_ALIGNED_HEADER));
    Header->OriginalPointer = RawBuffer;
    Header->Alignment = Alignment;
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
        ShadowStrikeFreePoolWithTag(OldBuffer, Tag);
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
    // Free old buffer
    //
    ShadowStrikeFreePoolWithTag(OldBuffer, Tag);

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
        MEMORY_TRACK_FREE(0); // Size unknown in this path
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
        MEMORY_TRACK_FREE(0); // Size unknown in this path
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeAligned(
    _In_opt_ _Post_ptr_invalid_ PVOID P
    )
{
    PSHADOWSTRIKE_ALIGNED_HEADER Header = NULL;

    if (P == NULL) {
        return;
    }

    //
    // Get header from just before the aligned buffer
    //
    Header = (PSHADOWSTRIKE_ALIGNED_HEADER)((ULONG_PTR)P - sizeof(SHADOWSTRIKE_ALIGNED_HEADER));

    //
    // Validate magic to catch corruption or invalid pointers
    //
    if (Header->Magic != SHADOWSTRIKE_ALIGNED_MAGIC) {
#if DBG
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike] ERROR: Invalid aligned pointer passed to ShadowStrikeFreeAligned: %p\n",
            P
        );
#endif
        //
        // In production, we cannot safely free this
        // Better to leak than corrupt or crash
        //
        return;
    }

    //
    // Clear magic to prevent double-free detection issues
    //
    Header->Magic = 0;

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
        return;
    }

    //
    // Securely wipe the memory before freeing
    //
    ShadowStrikeSecureWipeMemory(P, Size);

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
    // Initialize the appropriate lookaside list type
    //
    if (IsPaged) {
        ExInitializePagedLookasideList(
            &Lookaside->PagedList,
            NULL,   // Allocate function (use default)
            NULL,   // Free function (use default)
            0,      // Flags
            EntrySize,
            Tag,
            Depth
        );
    } else {
        ExInitializeNPagedLookasideList(
            &Lookaside->NonPagedList,
            NULL,   // Allocate function (use default)
            NULL,   // Free function (use default)
            0,      // Flags
            EntrySize,
            Tag,
            Depth
        );
    }

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
    // Probe the user buffer
    //
    __try {
        if (UserBuffer < MmHighestUserAddress) {
            ProbeForRead(UserBuffer, BufferSize, ProbeAlignment);
        } else {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    //
    // Allocate kernel buffer
    //
    SafeBuffer->KernelBuffer = ShadowStrikeAllocatePoolWithTag(
        PoolType,
        BufferSize,
        SHADOWSTRIKE_BUFFER_TAG
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
        ShadowStrikeFreePoolWithTag(SafeBuffer->KernelBuffer, SHADOWSTRIKE_BUFFER_TAG);
        RtlZeroMemory(SafeBuffer, sizeof(SHADOWSTRIKE_SAFE_BUFFER));
        return Status;
    }

    //
    // Fill in descriptor
    //
    SafeBuffer->OriginalUserBuffer = UserBuffer;
    SafeBuffer->Size = BufferSize;
    SafeBuffer->PoolTag = SHADOWSTRIKE_BUFFER_TAG;
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

    Status = ShadowStrikeCaptureUserBuffer(
        UserBuffer,
        BufferSize,
        sizeof(UCHAR),
        SafeBuffer,
        NonPagedPoolNx
    );

    if (NT_SUCCESS(Status)) {
        SafeBuffer->IsSecure = TRUE;
        SafeBuffer->PoolTag = SHADOWSTRIKE_SECURE_TAG;
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseUserBuffer(
    _Inout_ PSHADOWSTRIKE_SAFE_BUFFER SafeBuffer
    )
{
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
    // Free the kernel buffer
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

    __try {
        if (Buffer < MmHighestUserAddress) {
            ProbeForRead(Buffer, Length, Alignment);
        } else {
            return STATUS_ACCESS_VIOLATION;
        }
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

    __try {
        if (Buffer < MmHighestUserAddress) {
            ProbeForWrite(Buffer, Length, Alignment);
        } else {
            return STATUS_ACCESS_VIOLATION;
        }
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
    // Map to system address
    //
    SystemAddress = MmMapLockedPagesSpecifyCache(
        MappedMemory->Mdl,
        KernelMode,
        CacheType,
        NULL,
        FALSE,
        NormalPagePriority
    );

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

    if (Length > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    NewMdl = IoAllocateMdl(Buffer, (ULONG)Length, FALSE, FALSE, NULL);
    if (NewMdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Build MDL for non-paged kernel buffer
    //
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
    volatile UCHAR* VolatilePointer = NULL;

    if (Destination == NULL || Length == 0) {
        return;
    }

    //
    // Use volatile pointer to prevent compiler optimization
    //
    VolatilePointer = (volatile UCHAR*)Destination;

    while (Length--) {
        *VolatilePointer++ = 0;
    }

    //
    // Memory barrier to ensure all writes complete
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
    volatile UCHAR* VolatilePointer = NULL;
    SIZE_T i;

    if (Destination == NULL || Length == 0) {
        return;
    }

    //
    // DoD 5220.22-M secure wipe: three passes with different patterns
    //

    //
    // Pass 1: Zero pattern
    //
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = SHADOWSTRIKE_WIPE_PATTERN_1;
    }
    KeMemoryBarrier();

    //
    // Pass 2: 0xFF pattern
    //
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = SHADOWSTRIKE_WIPE_PATTERN_2;
    }
    KeMemoryBarrier();

    //
    // Pass 3: 0xAA pattern
    //
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = SHADOWSTRIKE_WIPE_PATTERN_3;
    }
    KeMemoryBarrier();

    //
    // Final pass: Zero
    //
    VolatilePointer = (volatile UCHAR*)Destination;
    for (i = 0; i < Length; i++) {
        VolatilePointer[i] = 0;
    }
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
    // On x64, kernel addresses are above 0xFFFF800000000000
    // MmHighestUserAddress points to the highest valid user-mode address
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
    //
    return (Address < MmHighestUserAddress);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsMemoryValid(
    _In_ PVOID Address,
    _In_ SIZE_T Length,
    _In_ BOOLEAN WriteAccess
    )
{
    PVOID EndAddress = NULL;

    if (Address == NULL || Length == 0) {
        return FALSE;
    }

    //
    // Check for address overflow
    //
    if ((ULONG_PTR)Address > (ULONG_PTR)(-1) - Length) {
        return FALSE;
    }

    EndAddress = (PVOID)((ULONG_PTR)Address + Length - 1);

    //
    // For kernel addresses, use MmIsAddressValid
    // Note: This only checks if the page is currently mapped, not if it's safe to access
    //
    if (ShadowStrikeIsKernelAddress(Address)) {
        //
        // Check first and last byte at minimum
        // For comprehensive checking, would need to check each page
        //
        if (!MmIsAddressValid(Address)) {
            return FALSE;
        }

        if (Length > 1 && !MmIsAddressValid(EndAddress)) {
            return FALSE;
        }

        return TRUE;
    }

    //
    // For user addresses, we cannot use MmIsAddressValid
    // Caller should use probing functions instead
    //
    return FALSE;
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
    _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple
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
        MmNonCached
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
    //
    if (NumberOfBytes > 0) {
        ShadowStrikeSecureZeroMemory(BaseAddress, NumberOfBytes);
    }

    MmFreeContiguousMemory(BaseAddress);

    MEMORY_TRACK_FREE(NumberOfBytes);
}
