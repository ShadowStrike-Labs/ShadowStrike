/*++
    ShadowStrike Next-Generation Antivirus
    Module: ParentChainTracker.h - Process ancestry tracking
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define PCT_POOL_TAG 'TCPP'
#define PCT_MAX_CHAIN_DEPTH 32

typedef struct _PCT_CHAIN_NODE {
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
    UNICODE_STRING CommandLine;
    LARGE_INTEGER CreateTime;
    BOOLEAN IsSystem;
    BOOLEAN IsSuspicious;
    LIST_ENTRY ListEntry;
} PCT_CHAIN_NODE, *PPCT_CHAIN_NODE;

typedef struct _PCT_PROCESS_CHAIN {
    HANDLE LeafProcessId;
    LIST_ENTRY ChainList;
    ULONG ChainDepth;
    BOOLEAN HasSuspiciousAncestor;
    BOOLEAN IsParentSpoofed;
    ULONG SuspicionScore;
    LIST_ENTRY ListEntry;
} PCT_PROCESS_CHAIN, *PPCT_PROCESS_CHAIN;

typedef struct _PCT_TRACKER {
    BOOLEAN Initialized;
    LIST_ENTRY ChainList;
    EX_PUSH_LOCK ChainLock;
    volatile LONG ChainCount;
    
    // Known suspicious parent-child patterns
    LIST_ENTRY SuspiciousPatterns;
    
    struct {
        volatile LONG64 ChainsBuilt;
        volatile LONG64 SpoofingDetected;
        LARGE_INTEGER StartTime;
    } Stats;
} PCT_TRACKER, *PPCT_TRACKER;

NTSTATUS PctInitialize(_Out_ PPCT_TRACKER* Tracker);
VOID PctShutdown(_Inout_ PPCT_TRACKER Tracker);
NTSTATUS PctBuildChain(_In_ PPCT_TRACKER Tracker, _In_ HANDLE ProcessId, _Out_ PPCT_PROCESS_CHAIN* Chain);
NTSTATUS PctDetectSpoofing(_In_ PPCT_TRACKER Tracker, _In_ HANDLE ProcessId, _In_ HANDLE ClaimedParentId, _Out_ PBOOLEAN IsSpoofed);
NTSTATUS PctCheckAncestry(_In_ PPCT_TRACKER Tracker, _In_ HANDLE ProcessId, _In_ PUNICODE_STRING AncestorName, _Out_ PBOOLEAN HasAncestor);
VOID PctFreeChain(_In_ PPCT_PROCESS_CHAIN Chain);

#ifdef __cplusplus
}
#endif
