/*++
    ShadowStrike Next-Generation Antivirus
    Module: NtdllIntegrity.h - Ntdll integrity monitoring
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define NI_POOL_TAG 'ININ'

typedef enum _NI_MODIFICATION {
    NiMod_None = 0,
    NiMod_HookInstalled,                // Detour/inline hook
    NiMod_InstructionPatch,             // Arbitrary instruction modification
    NiMod_SyscallStubModified,          // mov eax, X; syscall pattern broken
    NiMod_ImportModified,               // IAT hooking
    NiMod_ExportModified,               // EAT hooking
    NiMod_HeaderModified,               // PE header tampered
    NiMod_Unhooked,                     // Someone unhooked our hook
} NI_MODIFICATION;

typedef struct _NI_FUNCTION_STATE {
    CHAR FunctionName[64];
    PVOID ExpectedAddress;
    PVOID CurrentAddress;
    UCHAR ExpectedPrologue[16];
    UCHAR CurrentPrologue[16];
    BOOLEAN IsModified;
    NI_MODIFICATION ModificationType;
    LIST_ENTRY ListEntry;
} NI_FUNCTION_STATE, *PNI_FUNCTION_STATE;

typedef struct _NI_PROCESS_NTDLL {
    HANDLE ProcessId;
    PVOID NtdllBase;
    SIZE_T NtdllSize;
    UCHAR Hash[32];                     // SHA-256 of .text section
    
    // Function states
    LIST_ENTRY FunctionList;
    KSPIN_LOCK FunctionLock;
    ULONG FunctionCount;
    
    // Modification tracking
    ULONG ModificationCount;
    LARGE_INTEGER LastCheck;
    
    LIST_ENTRY ListEntry;
} NI_PROCESS_NTDLL, *PNI_PROCESS_NTDLL;

typedef struct _NI_MONITOR {
    BOOLEAN Initialized;
    
    // Clean ntdll reference
    PVOID CleanNtdllCopy;
    SIZE_T CleanNtdllSize;
    
    // Process tracking
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;
    
    struct {
        volatile LONG64 ProcessesMonitored;
        volatile LONG64 ModificationsFound;
        volatile LONG64 HooksDetected;
        LARGE_INTEGER StartTime;
    } Stats;
} NI_MONITOR, *PNI_MONITOR;

NTSTATUS NiInitialize(_Out_ PNI_MONITOR* Monitor);
VOID NiShutdown(_Inout_ PNI_MONITOR Monitor);
NTSTATUS NiScanProcess(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_ PNI_PROCESS_NTDLL* State);
NTSTATUS NiCheckFunction(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _In_ PCSTR FunctionName, _Out_ PNI_FUNCTION_STATE* State);
NTSTATUS NiDetectHooks(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_writes_to_(Max, *Count) PNI_FUNCTION_STATE* Hooks, _In_ ULONG Max, _Out_ PULONG Count);
NTSTATUS NiCompareToClean(_In_ PNI_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_ PBOOLEAN IsModified);
VOID NiFreeState(_In_ PNI_PROCESS_NTDLL State);

#ifdef __cplusplus
}
#endif
