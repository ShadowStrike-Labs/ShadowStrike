/*++
    ShadowStrike Next-Generation Antivirus
    Module: HeavensGateDetector.h - 32-64 bit transition detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define HGD_POOL_TAG 'DGHH'

typedef enum _HGD_GATE_TYPE {
    HgdGate_None = 0,
    HgdGate_HeavensGate,                // 32 -> 64 bit
    HgdGate_HellsGate,                  // Dynamic SSN from unhook
    HgdGate_WoW64Transition,            // Legitimate wow64cpu.dll
    HgdGate_ManualTransition,           // Handcrafted far call
} HGD_GATE_TYPE;

typedef struct _HGD_TRANSITION {
    HANDLE ProcessId;
    HANDLE ThreadId;
    
    HGD_GATE_TYPE Type;
    
    // Source context (32-bit)
    ULONG SourceCS;                     // Code segment
    PVOID SourceRIP;
    PVOID SourceRSP;
    
    // Target context (64-bit)
    ULONG TargetCS;
    PVOID TargetRIP;
    PVOID TargetRSP;
    
    // Syscall being executed
    ULONG SyscallNumber;
    ULONG64 SyscallArgs[8];
    
    // Module info
    UNICODE_STRING SourceModule;
    BOOLEAN IsFromWow64;
    
    ULONG SuspicionScore;
    LARGE_INTEGER Timestamp;
    LIST_ENTRY ListEntry;
} HGD_TRANSITION, *PHGD_TRANSITION;

typedef struct _HGD_DETECTOR {
    BOOLEAN Initialized;
    
    // Wow64 addresses
    PVOID Wow64TransitionAddress;
    PVOID Wow64SystemServiceAddress;
    
    // Transitions
    LIST_ENTRY TransitionList;
    EX_PUSH_LOCK TransitionLock;
    volatile LONG TransitionCount;
    
    struct {
        volatile LONG64 TransitionsDetected;
        volatile LONG64 LegitimateTransitions;
        volatile LONG64 SuspiciousTransitions;
        LARGE_INTEGER StartTime;
    } Stats;
} HGD_DETECTOR, *PHGD_DETECTOR;

NTSTATUS HgdInitialize(_Out_ PHGD_DETECTOR* Detector);
VOID HgdShutdown(_Inout_ PHGD_DETECTOR Detector);
NTSTATUS HgdAnalyzeTransition(_In_ PHGD_DETECTOR Detector, _In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ PVOID TransitionAddress, _Out_ PHGD_TRANSITION* Transition);
NTSTATUS HgdIsLegitimateWow64(_In_ PHGD_DETECTOR Detector, _In_ PVOID Address, _Out_ PBOOLEAN IsLegitimate);
NTSTATUS HgdGetTransitions(_In_ PHGD_DETECTOR Detector, _In_ HANDLE ProcessId, _Out_writes_to_(Max, *Count) PHGD_TRANSITION* Transitions, _In_ ULONG Max, _Out_ PULONG Count);
VOID HgdFreeTransition(_In_ PHGD_TRANSITION Transition);

#ifdef __cplusplus
}
#endif
