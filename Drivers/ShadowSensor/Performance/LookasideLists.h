/*++
    ShadowStrike Next-Generation Antivirus
    Module: LookasideLists.h - Lookaside list management
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define LL_POOL_TAG 'LSLL'

typedef struct _LL_LOOKASIDE {
    CHAR Name[32];
    ULONG Tag;
    SIZE_T Size;
    POOL_TYPE PoolType;
    
    // Native lookaside
    union {
        NPAGED_LOOKASIDE_LIST NonPaged;
        PAGED_LOOKASIDE_LIST Paged;
    } List;
    BOOLEAN IsPaged;
    
    // Statistics
    struct {
        volatile LONG64 Allocations;
        volatile LONG64 Frees;
        volatile LONG64 Hits;
        volatile LONG64 Misses;
    } Stats;
    
    LIST_ENTRY ListEntry;
} LL_LOOKASIDE, *PLL_LOOKASIDE;

typedef struct _LL_MANAGER {
    BOOLEAN Initialized;
    
    LIST_ENTRY LookasideList;
    EX_PUSH_LOCK Lock;
    ULONG LookasideCount;
    
    struct {
        volatile LONG64 TotalAllocations;
        volatile LONG64 TotalFrees;
        LARGE_INTEGER StartTime;
    } GlobalStats;
} LL_MANAGER, *PLL_MANAGER;

NTSTATUS LlInitialize(_Out_ PLL_MANAGER* Manager);
VOID LlShutdown(_Inout_ PLL_MANAGER Manager);
NTSTATUS LlCreateLookaside(_In_ PLL_MANAGER Manager, _In_ PCSTR Name, _In_ ULONG Tag, _In_ SIZE_T Size, _In_ BOOLEAN Paged, _Out_ PLL_LOOKASIDE* Lookaside);
NTSTATUS LlDestroyLookaside(_In_ PLL_MANAGER Manager, _In_ PLL_LOOKASIDE Lookaside);
PVOID LlAllocate(_In_ PLL_LOOKASIDE Lookaside);
VOID LlFree(_In_ PLL_LOOKASIDE Lookaside, _In_ PVOID Block);
NTSTATUS LlGetStats(_In_ PLL_LOOKASIDE Lookaside, _Out_ PULONG64 Hits, _Out_ PULONG64 Misses);

#ifdef __cplusplus
}
#endif
