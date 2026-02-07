/**
 * ============================================================================
 * ShadowStrike NGAV - KERNEL MEMORY UTILITIES
 * ============================================================================
 *
 * @file MemoryUtils.c
 * @brief Implementation of safe memory allocation wrappers.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MemoryUtils.h"

//
// Use ExAllocatePool2 for Windows 10 version 2004+ (Target OS)
// If targeting older OS, use ExAllocatePoolWithTag.
//
// We defined POOL_ZERO_DOWN_LEVEL_SUPPORT in project settings usually,
// but here we will implement a safe wrapper.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeAllocatePoolWithTag)
// Free can be called at dispatch level, so it must be non-paged code
// unless we are sure we are at APC_LEVEL or lower.
#endif

_Check_return_
_Ret_maybenull_
PVOID
ShadowStrikeAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    )
{
    PVOID Buffer = NULL;

    //
    // Sanity check
    //
    if (NumberOfBytes == 0) {
        return NULL;
    }

    //
    // Use ExAllocatePool2 if available (safer, zeroes memory by default).
    // Note: POOL_FLAG_NON_PAGED is 0x0000000000000040UI64
    //
    // For wider compatibility or if ExAllocatePool2 isn't defined in the WDK environment:
    // We stick to ExAllocatePoolWithTag but zero the memory.
    //

#pragma warning(push)
#pragma warning(disable: 4996) // Deprecated ExAllocatePoolWithTag warning

    Buffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

#pragma warning(pop)

    if (Buffer) {
        RtlZeroMemory(Buffer, NumberOfBytes);
    }

    return Buffer;
}

VOID
ShadowStrikeFreePool(
    _In_ PVOID P
    )
{
    if (P) {
        ExFreePool(P);
    }
}

VOID
ShadowStrikeFreePoolWithTag(
    _In_ PVOID P,
    _In_ ULONG Tag
    )
{
    if (P) {
        ExFreePoolWithTag(P, Tag);
    }
}
