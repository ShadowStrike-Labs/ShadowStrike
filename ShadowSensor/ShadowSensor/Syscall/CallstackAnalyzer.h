/*++
    ShadowStrike Next-Generation Antivirus
    Module: CallstackAnalyzer.h - Call stack analysis and validation
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define CSA_POOL_TAG 'ASAC'
#define CSA_MAX_FRAMES 64

typedef enum _CSA_FRAME_TYPE {
    CsaFrame_Unknown = 0,
    CsaFrame_Kernel,
    CsaFrame_User,
    CsaFrame_Transition,
    CsaFrame_SystemCall,
} CSA_FRAME_TYPE;

typedef enum _CSA_ANOMALY {
    CsaAnomaly_None                 = 0x00000000,
    CsaAnomaly_UnbackedCode         = 0x00000001,
    CsaAnomaly_RWXMemory            = 0x00000002,
    CsaAnomaly_StackPivot           = 0x00000004,
    CsaAnomaly_MissingFrames        = 0x00000008,
    CsaAnomaly_SpoofedFrames        = 0x00000010,
    CsaAnomaly_UnknownModule        = 0x00000020,
    CsaAnomaly_DirectSyscall        = 0x00000040,
    CsaAnomaly_ReturnGadget         = 0x00000080,
} CSA_ANOMALY;

typedef struct _CSA_STACK_FRAME {
    PVOID ReturnAddress;
    PVOID FramePointer;
    PVOID StackPointer;
    
    // Module info
    PVOID ModuleBase;
    UNICODE_STRING ModuleName;
    ULONG64 OffsetInModule;
    
    // Analysis
    CSA_FRAME_TYPE Type;
    BOOLEAN IsBackedByImage;
    ULONG MemoryProtection;
    
    CSA_ANOMALY AnomalyFlags;
} CSA_STACK_FRAME, *PCSA_STACK_FRAME;

typedef struct _CSA_CALLSTACK {
    HANDLE ProcessId;
    HANDLE ThreadId;
    
    CSA_STACK_FRAME Frames[CSA_MAX_FRAMES];
    ULONG FrameCount;
    
    // Overall analysis
    CSA_ANOMALY AggregatedAnomalies;
    ULONG SuspicionScore;
    
    LARGE_INTEGER CaptureTime;
} CSA_CALLSTACK, *PCSA_CALLSTACK;

typedef struct _CSA_ANALYZER {
    BOOLEAN Initialized;
    
    // Module cache
    LIST_ENTRY ModuleCache;
    EX_PUSH_LOCK ModuleLock;
    
    struct {
        volatile LONG64 StacksCaptured;
        volatile LONG64 AnomaliesFound;
        LARGE_INTEGER StartTime;
    } Stats;
} CSA_ANALYZER, *PCSA_ANALYZER;

NTSTATUS CsaInitialize(_Out_ PCSA_ANALYZER* Analyzer);
VOID CsaShutdown(_Inout_ PCSA_ANALYZER Analyzer);
NTSTATUS CsaCaptureCallstack(_In_ PCSA_ANALYZER Analyzer, _In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _Out_ PCSA_CALLSTACK* Callstack);
NTSTATUS CsaAnalyzeCallstack(_In_ PCSA_ANALYZER Analyzer, _In_ PCSA_CALLSTACK Callstack, _Out_ PCSA_ANOMALY Anomalies, _Out_ PULONG Score);
NTSTATUS CsaValidateReturnAddresses(_In_ PCSA_ANALYZER Analyzer, _In_ PCSA_CALLSTACK Callstack, _Out_ PBOOLEAN AllValid);
NTSTATUS CsaDetectStackPivot(_In_ PCSA_ANALYZER Analyzer, _In_ HANDLE ThreadId, _Out_ PBOOLEAN IsPivoted);
VOID CsaFreeCallstack(_In_ PCSA_CALLSTACK Callstack);

#ifdef __cplusplus
}
#endif
