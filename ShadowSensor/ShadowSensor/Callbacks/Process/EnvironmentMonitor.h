/*++
    ShadowStrike Next-Generation Antivirus
    Module: EnvironmentMonitor.h - Environment variable tracking
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define EM_POOL_TAG 'NOME'
#define EM_MAX_ENV_NAME 256
#define EM_MAX_ENV_VALUE 32768

typedef enum _EM_SUSPICION {
    EmSuspicion_None                = 0x00000000,
    EmSuspicion_ModifiedPath        = 0x00000001,
    EmSuspicion_DLLSearchOrder      = 0x00000002,
    EmSuspicion_ProxySettings       = 0x00000004,
    EmSuspicion_TempOverride        = 0x00000008,
    EmSuspicion_HiddenVariable      = 0x00000010,
    EmSuspicion_EncodedValue        = 0x00000020,
} EM_SUSPICION;

typedef struct _EM_ENV_VARIABLE {
    CHAR Name[EM_MAX_ENV_NAME];
    CHAR Value[EM_MAX_ENV_VALUE];
    LARGE_INTEGER LastModified;
    BOOLEAN IsSystemVariable;
    LIST_ENTRY ListEntry;
} EM_ENV_VARIABLE, *PEM_ENV_VARIABLE;

typedef struct _EM_PROCESS_ENV {
    HANDLE ProcessId;
    LIST_ENTRY VariableList;
    KSPIN_LOCK Lock;
    ULONG VariableCount;
    EM_SUSPICION SuspicionFlags;
    LIST_ENTRY ListEntry;
} EM_PROCESS_ENV, *PEM_PROCESS_ENV;

typedef struct _EM_MONITOR {
    BOOLEAN Initialized;
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;
    
    struct {
        volatile LONG64 ProcessesMonitored;
        volatile LONG64 SuspiciousEnvFound;
        LARGE_INTEGER StartTime;
    } Stats;
} EM_MONITOR, *PEM_MONITOR;

NTSTATUS EmInitialize(_Out_ PEM_MONITOR* Monitor);
VOID EmShutdown(_Inout_ PEM_MONITOR Monitor);
NTSTATUS EmCaptureEnvironment(_In_ PEM_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_ PEM_PROCESS_ENV* Env);
NTSTATUS EmAnalyzeEnvironment(_In_ PEM_MONITOR Monitor, _In_ PEM_PROCESS_ENV Env, _Out_ PEM_SUSPICION* Flags);
NTSTATUS EmGetVariable(_In_ PEM_PROCESS_ENV Env, _In_ PCSTR Name, _Out_ PEM_ENV_VARIABLE* Variable);
VOID EmFreeEnvironment(_In_ PEM_PROCESS_ENV Env);

#ifdef __cplusplus
}
#endif
