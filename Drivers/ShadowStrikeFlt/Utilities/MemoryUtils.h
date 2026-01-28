/**
 * ============================================================================
 * ShadowStrike NGAV - KERNEL MEMORY UTILITIES
 * ============================================================================
 *
 * @file MemoryUtils.h
 * @brief Safe memory allocation wrappers with pool tagging.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_MEMORY_UTILS_H_
#define _SHADOWSTRIKE_MEMORY_UTILS_H_

#include <fltKernel.h>

//
// Pool Tag: 'SsFt' (ShadowStrike Filter)
// Reversing the bytes for little-endian: 'tFsS'
//
#define SHADOWSTRIKE_POOL_TAG 'tFsS'

//
// Macro for allocation to capture line number/file in debug builds if needed
//
#define ShadowStrikeAllocate(Size) \
    ShadowStrikeAllocatePoolWithTag(NonPagedPoolNx, Size, SHADOWSTRIKE_POOL_TAG)

#define ShadowStrikeAllocatePaged(Size) \
    ShadowStrikeAllocatePoolWithTag(PagedPool, Size, SHADOWSTRIKE_POOL_TAG)

//
// Function Prototypes
//

_Check_return_
_Ret_maybenull_
PVOID
ShadowStrikeAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

VOID
ShadowStrikeFreePool(
    _In_ PVOID P
    );

VOID
ShadowStrikeFreePoolWithTag(
    _In_ PVOID P,
    _In_ ULONG Tag
    );

#endif // _SHADOWSTRIKE_MEMORY_UTILS_H_
