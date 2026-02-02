/*++
    ShadowStrike Next-Generation Antivirus
    Module: HandleTracker.h - Handle forensics and tracking
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define HT_POOL_TAG 'KRTH'
#define HT_MAX_HANDLES_PER_PROCESS 65536

typedef enum _HT_HANDLE_TYPE {
    HtType_Unknown = 0,
    HtType_Process,
    HtType_Thread,
    HtType_File,
    HtType_Key,
    HtType_Section,
    HtType_Token,
    HtType_Event,
    HtType_Semaphore,
    HtType_Mutex,
    HtType_Timer,
    HtType_Port,
    HtType_Device,
    HtType_Driver,
} HT_HANDLE_TYPE;

typedef enum _HT_SUSPICION {
    HtSuspicion_None                = 0x00000000,
    HtSuspicion_CrossProcess        = 0x00000001,
    HtSuspicion_HighPrivilege       = 0x00000002,
    HtSuspicion_DuplicatedIn        = 0x00000004,
    HtSuspicion_SensitiveTarget     = 0x00000008,
    HtSuspicion_ManyHandles         = 0x00000010,
    HtSuspicion_SystemHandle        = 0x00000020,
} HT_SUSPICION;

typedef struct _HT_HANDLE_ENTRY {
    HANDLE Handle;
    HT_HANDLE_TYPE Type;
    ACCESS_MASK GrantedAccess;
    
    // Target info
    PVOID ObjectPointer;
    HANDLE TargetProcessId;             // For process/thread handles
    UNICODE_STRING ObjectName;
    
    // Source
    BOOLEAN IsDuplicated;
    HANDLE DuplicatedFromProcess;
    
    // Suspicion
    HT_SUSPICION SuspicionFlags;
    
    LIST_ENTRY ListEntry;
} HT_HANDLE_ENTRY, *PHT_HANDLE_ENTRY;

typedef struct _HT_PROCESS_HANDLES {
    HANDLE ProcessId;
    LIST_ENTRY HandleList;
    KSPIN_LOCK Lock;
    volatile LONG HandleCount;
    HT_SUSPICION AggregatedSuspicion;
    LIST_ENTRY ListEntry;
} HT_PROCESS_HANDLES, *PHT_PROCESS_HANDLES;

typedef struct _HT_TRACKER {
    BOOLEAN Initialized;
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;
    
    struct {
        volatile LONG64 HandlesTracked;
        volatile LONG64 SuspiciousHandles;
        volatile LONG64 CrossProcessHandles;
        LARGE_INTEGER StartTime;
    } Stats;
} HT_TRACKER, *PHT_TRACKER;

NTSTATUS HtInitialize(_Out_ PHT_TRACKER* Tracker);
VOID HtShutdown(_Inout_ PHT_TRACKER Tracker);
NTSTATUS HtSnapshotHandles(_In_ PHT_TRACKER Tracker, _In_ HANDLE ProcessId, _Out_ PHT_PROCESS_HANDLES* Handles);
NTSTATUS HtRecordDuplication(_In_ PHT_TRACKER Tracker, _In_ HANDLE SourceProcess, _In_ HANDLE TargetProcess, _In_ HANDLE SourceHandle, _In_ HANDLE TargetHandle);
NTSTATUS HtAnalyzeHandles(_In_ PHT_TRACKER Tracker, _In_ PHT_PROCESS_HANDLES Handles, _Out_ PHT_SUSPICION Flags);
NTSTATUS HtFindCrossProcessHandles(_In_ PHT_TRACKER Tracker, _In_ HANDLE TargetProcessId, _Out_writes_to_(Max, *Count) PHT_HANDLE_ENTRY* Entries, _In_ ULONG Max, _Out_ PULONG Count);
VOID HtFreeHandles(_In_ PHT_PROCESS_HANDLES Handles);

#ifdef __cplusplus
}
#endif
