/*++
    ShadowStrike Next-Generation Antivirus
    Module: TelemetryEvents.h - ETW event definitions
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <evntrace.h>

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(SHADOWSTRIKE_ETW_PROVIDER, 0xA1B2C3D4, 0xE5F6, 0x7890, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90);

#define TE_POOL_TAG 'ETET'

typedef enum _TE_EVENT_LEVEL {
    TeLevel_Critical = 1,
    TeLevel_Error = 2,
    TeLevel_Warning = 3,
    TeLevel_Info = 4,
    TeLevel_Verbose = 5,
} TE_EVENT_LEVEL;

typedef enum _TE_EVENT_KEYWORD {
    TeKeyword_Process       = 0x0001,
    TeKeyword_Thread        = 0x0002,
    TeKeyword_Image         = 0x0004,
    TeKeyword_File          = 0x0008,
    TeKeyword_Registry      = 0x0010,
    TeKeyword_Network       = 0x0020,
    TeKeyword_Memory        = 0x0040,
    TeKeyword_Security      = 0x0080,
    TeKeyword_Detection     = 0x0100,
    TeKeyword_Performance   = 0x0200,
    TeKeyword_Debug         = 0x8000,
} TE_EVENT_KEYWORD;

typedef enum _TE_EVENT_ID {
    // Process events 1-99
    TeEvent_ProcessCreate = 1,
    TeEvent_ProcessTerminate = 2,
    TeEvent_ProcessOpen = 3,
    
    // Thread events 100-199
    TeEvent_ThreadCreate = 100,
    TeEvent_ThreadTerminate = 101,
    TeEvent_ThreadOpen = 102,
    
    // Image events 200-299
    TeEvent_ImageLoad = 200,
    TeEvent_ImageUnload = 201,
    
    // File events 300-399
    TeEvent_FileCreate = 300,
    TeEvent_FileRead = 301,
    TeEvent_FileWrite = 302,
    TeEvent_FileDelete = 303,
    TeEvent_FileRename = 304,
    
    // Registry events 400-499
    TeEvent_RegCreate = 400,
    TeEvent_RegOpen = 401,
    TeEvent_RegSetValue = 402,
    TeEvent_RegDeleteKey = 403,
    TeEvent_RegDeleteValue = 404,
    
    // Network events 500-599
    TeEvent_NetConnect = 500,
    TeEvent_NetListen = 501,
    TeEvent_NetSend = 502,
    TeEvent_NetReceive = 503,
    TeEvent_DnsQuery = 504,
    
    // Detection events 600-699
    TeEvent_ThreatDetected = 600,
    TeEvent_ThreatBlocked = 601,
    TeEvent_SuspiciousBehavior = 602,
    TeEvent_AttackChain = 603,
    
    // Performance events 700-799
    TeEvent_PerformanceCounter = 700,
    TeEvent_ResourceUsage = 701,
    
} TE_EVENT_ID;

typedef struct _TE_PROVIDER {
    BOOLEAN Initialized;
    REGHANDLE RegistrationHandle;
    
    ULONG64 EnabledKeywords;
    UCHAR EnabledLevel;
    BOOLEAN IsEnabled;
    
    struct {
        volatile LONG64 EventsWritten;
        volatile LONG64 EventsDropped;
        LARGE_INTEGER StartTime;
    } Stats;
} TE_PROVIDER, *PTE_PROVIDER;

NTSTATUS TeInitialize(_Out_ PTE_PROVIDER* Provider);
VOID TeShutdown(_Inout_ PTE_PROVIDER Provider);
BOOLEAN TeIsEnabled(_In_ PTE_PROVIDER Provider, _In_ UCHAR Level, _In_ ULONG64 Keywords);
NTSTATUS TeWriteEvent(_In_ PTE_PROVIDER Provider, _In_ TE_EVENT_ID EventId, _In_ UCHAR Level, _In_ ULONG64 Keywords, _In_ ULONG FieldCount, ...);
NTSTATUS TeWriteProcessEvent(_In_ PTE_PROVIDER Provider, _In_ TE_EVENT_ID EventId, _In_ HANDLE ProcessId, _In_ PUNICODE_STRING ImagePath, _In_opt_ PUNICODE_STRING CommandLine);
NTSTATUS TeWriteDetectionEvent(_In_ PTE_PROVIDER Provider, _In_ HANDLE ProcessId, _In_ PCSTR ThreatName, _In_ ULONG ThreatScore, _In_ PCSTR MITRETechnique);

#ifdef __cplusplus
}
#endif
