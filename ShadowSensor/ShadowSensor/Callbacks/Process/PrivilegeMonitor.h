/*++
    ShadowStrike Next-Generation Antivirus
    Module: PrivilegeMonitor.h - Privilege escalation detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define PM_POOL_TAG 'NOMP'

typedef enum _PM_ESCALATION_TYPE {
    PmEscalation_None = 0,
    PmEscalation_PrivilegeEnable,
    PmEscalation_TokenElevation,
    PmEscalation_IntegrityIncrease,
    PmEscalation_UACBypass,
    PmEscalation_ServiceCreation,
    PmEscalation_DriverLoad,
    PmEscalation_ExploitKernel,
} PM_ESCALATION_TYPE;

typedef struct _PM_ESCALATION_EVENT {
    PM_ESCALATION_TYPE Type;
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    
    // Before/after state
    ULONG OldIntegrityLevel;
    ULONG NewIntegrityLevel;
    ULONG OldPrivileges;
    ULONG NewPrivileges;
    
    // Detection
    BOOLEAN IsLegitimate;
    ULONG SuspicionScore;
    CHAR Technique[64];
    
    LARGE_INTEGER Timestamp;
    LIST_ENTRY ListEntry;
} PM_ESCALATION_EVENT, *PPM_ESCALATION_EVENT;

typedef struct _PM_MONITOR {
    BOOLEAN Initialized;
    
    // Process baseline
    LIST_ENTRY ProcessBaselines;
    EX_PUSH_LOCK BaselineLock;
    
    // Events
    LIST_ENTRY EventList;
    KSPIN_LOCK EventLock;
    volatile LONG EventCount;
    
    struct {
        volatile LONG64 EscalationsDetected;
        volatile LONG64 LegitimateEscalations;
        LARGE_INTEGER StartTime;
    } Stats;
} PM_MONITOR, *PPM_MONITOR;

NTSTATUS PmInitialize(_Out_ PPM_MONITOR* Monitor);
VOID PmShutdown(_Inout_ PPM_MONITOR Monitor);
NTSTATUS PmRecordBaseline(_In_ PPM_MONITOR Monitor, _In_ HANDLE ProcessId);
NTSTATUS PmCheckForEscalation(_In_ PPM_MONITOR Monitor, _In_ HANDLE ProcessId, _Out_ PPM_ESCALATION_EVENT* Event);
NTSTATUS PmGetEvents(_In_ PPM_MONITOR Monitor, _Out_writes_to_(Max, *Count) PPM_ESCALATION_EVENT* Events, _In_ ULONG Max, _Out_ PULONG Count);
VOID PmFreeEvent(_In_ PPM_ESCALATION_EVENT Event);

#ifdef __cplusplus
}
#endif
