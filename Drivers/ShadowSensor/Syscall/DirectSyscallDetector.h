/*++
    ShadowStrike Next-Generation Antivirus
    Module: DirectSyscallDetector.h - Direct syscall abuse detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define DSD_POOL_TAG 'DSSD'

typedef enum _DSD_TECHNIQUE {
    DsdTechnique_None = 0,
    DsdTechnique_DirectSyscall,         // mov eax, SSDT#; syscall
    DsdTechnique_IndirectSyscall,       // jmp to ntdll syscall stub
    DsdTechnique_Manual,                // Manual SSDT resolution
    DsdTechnique_HeavensGate,           // 32->64 bit transition
    DsdTechnique_HellsGate,             // Dynamic SSN resolution
    DsdTechnique_HalosGate,             // Neighbor syscall walking
    DsdTechnique_TartarusGate,          // Exception-based resolution
    DsdTechnique_SysWhispers,           // SysWhispers patterns
} DSD_TECHNIQUE;

typedef struct _DSD_DETECTION {
    HANDLE ProcessId;
    HANDLE ThreadId;
    
    DSD_TECHNIQUE Technique;
    ULONG SyscallNumber;
    PVOID CallerAddress;
    PVOID StackPointer;
    
    // Call stack analysis
    PVOID ReturnAddresses[16];
    ULONG ReturnAddressCount;
    BOOLEAN CallFromNtdll;
    BOOLEAN CallFromKnownModule;
    
    // Module info
    UNICODE_STRING CallerModule;
    ULONG64 CallerModuleBase;
    ULONG64 CallerOffset;
    
    ULONG SuspicionScore;
    LARGE_INTEGER Timestamp;
    LIST_ENTRY ListEntry;
} DSD_DETECTION, *PDSD_DETECTION;

typedef struct _DSD_DETECTOR {
    BOOLEAN Initialized;
    
    // Detection records
    LIST_ENTRY DetectionList;
    EX_PUSH_LOCK DetectionLock;
    volatile LONG DetectionCount;
    
    // Known good patterns
    LIST_ENTRY WhitelistPatterns;
    
    struct {
        volatile LONG64 SyscallsAnalyzed;
        volatile LONG64 DirectCalls;
        volatile LONG64 IndirectCalls;
        volatile LONG64 HeavensGateCalls;
        LARGE_INTEGER StartTime;
    } Stats;
} DSD_DETECTOR, *PDSD_DETECTOR;

NTSTATUS DsdInitialize(_Out_ PDSD_DETECTOR* Detector);
VOID DsdShutdown(_Inout_ PDSD_DETECTOR Detector);
NTSTATUS DsdAnalyzeSyscall(_In_ PDSD_DETECTOR Detector, _In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ PVOID CallerAddress, _In_ ULONG SyscallNumber, _Out_ PDSD_DETECTION* Detection);
NTSTATUS DsdDetectTechnique(_In_ PDSD_DETECTOR Detector, _In_ PVOID Address, _In_ ULONG Length, _Out_ PDSD_TECHNIQUE Technique);
NTSTATUS DsdValidateCallstack(_In_ PDSD_DETECTOR Detector, _In_ HANDLE ThreadId, _Out_ PBOOLEAN IsValid, _Out_opt_ PDSD_TECHNIQUE Technique);
VOID DsdFreeDetection(_In_ PDSD_DETECTION Detection);

#ifdef __cplusplus
}
#endif
