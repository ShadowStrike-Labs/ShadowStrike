/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PRIVILEGE ESCALATION MONITOR
===============================================================================

@file PrivilegeMonitor.h
@brief Enterprise-grade privilege escalation detection for kernel EDR.

This module provides comprehensive privilege escalation monitoring:
- Process privilege baseline capture and tracking
- Token elevation detection (integrity level changes)
- Privilege enable/disable monitoring
- UAC bypass detection patterns
- Service creation privilege abuse
- Driver load privilege monitoring
- Kernel exploit signature detection
- Token stealing and manipulation detection
- Cross-session privilege escalation

Detection Techniques Covered (MITRE ATT&CK):
- T1548: Abuse Elevation Control Mechanism
- T1548.002: Bypass User Account Control
- T1134: Access Token Manipulation
- T1134.001: Token Impersonation/Theft
- T1134.002: Create Process with Token
- T1134.003: Make and Impersonate Token
- T1543: Create or Modify System Process
- T1543.003: Windows Service
- T1068: Exploitation for Privilege Escalation

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags
//
#define PM_POOL_TAG                     'NOMP'
#define PM_BASELINE_POOL_TAG            'lBMP'
#define PM_EVENT_POOL_TAG               'vEMP'
#define PM_WORK_POOL_TAG                'kWMP'

//
// Limits
//
#define PM_MAX_BASELINES                8192
#define PM_MAX_EVENTS                   4096
#define PM_MAX_PROCESS_NAME_LEN         260
#define PM_MAX_COMMAND_LINE_LEN         512
#define PM_MAX_TECHNIQUE_LEN            64

//
// Integrity level values (matching Windows SID values)
//
#define PM_INTEGRITY_UNTRUSTED          0x0000
#define PM_INTEGRITY_LOW                0x1000
#define PM_INTEGRITY_MEDIUM             0x2000
#define PM_INTEGRITY_MEDIUM_PLUS        0x2100
#define PM_INTEGRITY_HIGH               0x3000
#define PM_INTEGRITY_SYSTEM             0x4000
#define PM_INTEGRITY_PROTECTED          0x5000

//
// Privilege bit flags for tracking
//
#define PM_PRIV_NONE                    0x00000000
#define PM_PRIV_DEBUG                   0x00000001
#define PM_PRIV_IMPERSONATE             0x00000002
#define PM_PRIV_ASSIGN_PRIMARY          0x00000004
#define PM_PRIV_TCB                     0x00000008
#define PM_PRIV_LOAD_DRIVER             0x00000010
#define PM_PRIV_BACKUP                  0x00000020
#define PM_PRIV_RESTORE                 0x00000040
#define PM_PRIV_TAKE_OWNERSHIP          0x00000080
#define PM_PRIV_CREATE_TOKEN            0x00000100
#define PM_PRIV_SECURITY                0x00000200
#define PM_PRIV_SYSTEM_ENVIRONMENT      0x00000400
#define PM_PRIV_INCREASE_QUOTA          0x00000800
#define PM_PRIV_INCREASE_PRIORITY       0x00001000
#define PM_PRIV_CREATE_PAGEFILE         0x00002000
#define PM_PRIV_SHUTDOWN                0x00004000
#define PM_PRIV_AUDIT                   0x00008000
#define PM_PRIV_SYSTEM_PROFILE          0x00010000
#define PM_PRIV_SYSTEMTIME              0x00020000
#define PM_PRIV_MANAGE_VOLUME           0x00040000

//
// Suspicion thresholds
//
#define PM_SUSPICION_NONE               0
#define PM_SUSPICION_LOW                20
#define PM_SUSPICION_MEDIUM             45
#define PM_SUSPICION_HIGH               70
#define PM_SUSPICION_CRITICAL           90

//
// Escalation types
//
typedef enum _PM_ESCALATION_TYPE {
    PmEscalation_None = 0,
    PmEscalation_PrivilegeEnable,
    PmEscalation_TokenElevation,
    PmEscalation_IntegrityIncrease,
    PmEscalation_UACBypass,
    PmEscalation_ServiceCreation,
    PmEscalation_DriverLoad,
    PmEscalation_ExploitKernel,
    PmEscalation_TokenManipulation,
    PmEscalation_CrossSession,
    PmEscalation_Max
} PM_ESCALATION_TYPE;

//
// Event flags
//
#define PM_EVENT_FLAG_LEGITIMATE        0x00000001
#define PM_EVENT_FLAG_ALERTABLE         0x00000002
#define PM_EVENT_FLAG_BLOCKED           0x00000004
#define PM_EVENT_FLAG_REPORTED          0x00000008

//
// Escalation event (self-contained, no external dependencies)
//
typedef struct _PM_ESCALATION_EVENT {
    //
    // Type and identification
    //
    PM_ESCALATION_TYPE Type;
    HANDLE ProcessId;
    HANDLE ParentProcessId;

    //
    // Process name (embedded, null-terminated)
    //
    WCHAR ProcessName[PM_MAX_PROCESS_NAME_LEN];
    WCHAR ParentProcessName[PM_MAX_PROCESS_NAME_LEN];

    //
    // Before/after state
    //
    ULONG OldIntegrityLevel;
    ULONG NewIntegrityLevel;
    ULONG OldPrivileges;
    ULONG NewPrivileges;
    ULONG OldSessionId;
    ULONG NewSessionId;

    //
    // Authentication tracking
    //
    LUID OldAuthenticationId;
    LUID NewAuthenticationId;

    //
    // Detection metadata
    //
    ULONG Flags;
    ULONG SuspicionScore;
    CHAR Technique[PM_MAX_TECHNIQUE_LEN];

    //
    // Timing
    //
    LARGE_INTEGER Timestamp;
    LARGE_INTEGER BaselineTime;

    //
    // Reference counting for safe access
    //
    volatile LONG RefCount;

    //
    // List linkage (internal use)
    //
    LIST_ENTRY ListEntry;

} PM_ESCALATION_EVENT, *PPM_ESCALATION_EVENT;

//
// Monitor statistics
//
typedef struct _PM_STATISTICS {
    volatile LONG64 EscalationsDetected;
    volatile LONG64 LegitimateEscalations;
    volatile LONG64 BlockedEscalations;
    volatile LONG64 BaselinesCaptured;
    volatile LONG64 BaselinesRemoved;
    volatile LONG CurrentBaselineCount;
    volatile LONG CurrentEventCount;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastCleanupTime;
} PM_STATISTICS, *PPM_STATISTICS;

//
// Monitor configuration
//
typedef struct _PM_CONFIG {
    BOOLEAN EnableIntegrityMonitoring;
    BOOLEAN EnablePrivilegeMonitoring;
    BOOLEAN EnableUACBypassDetection;
    BOOLEAN EnableTokenManipulationDetection;
    BOOLEAN EnableCrossSessionDetection;
    BOOLEAN AlertOnEscalation;
    BOOLEAN BlockHighRiskEscalation;
    ULONG MinAlertScore;
    ULONG BlockThresholdScore;
} PM_CONFIG, *PPM_CONFIG;

//
// Opaque monitor handle
//
typedef struct _PM_MONITOR *PPM_MONITOR;

//
// Initialization and cleanup
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmInitialize(
    _Out_ PPM_MONITOR* Monitor
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
PmShutdown(
    _Inout_ PPM_MONITOR Monitor
    );

//
// Configuration
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmGetConfiguration(
    _In_ PPM_MONITOR Monitor,
    _Out_ PPM_CONFIG Config
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmSetConfiguration(
    _In_ PPM_MONITOR Monitor,
    _In_ PPM_CONFIG Config
    );

//
// Baseline management
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmRecordBaseline(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmRemoveBaseline(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmMarkProcessTerminated(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    );

//
// Escalation detection
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmCheckForEscalation(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Outptr_opt_ PPM_ESCALATION_EVENT* Event
    );

//
// Event management
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PmReferenceEvent(
    _In_ PPM_ESCALATION_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PmDereferenceEvent(
    _In_ PPM_ESCALATION_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PmGetEvents(
    _In_ PPM_MONITOR Monitor,
    _Out_writes_to_(MaxEvents, *EventCount) PPM_ESCALATION_EVENT* Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventCount
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PmClearEvents(
    _In_ PPM_MONITOR Monitor
    );

//
// Query APIs
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PmQueryProcessEscalation(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN HasEscalated,
    _Out_ PULONG EscalationCount,
    _Out_ PULONG CurrentIntegrityLevel
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PmGetStatistics(
    _In_ PPM_MONITOR Monitor,
    _Out_ PPM_STATISTICS Statistics
    );

//
// Validation
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
PmIsValidMonitor(
    _In_opt_ PPM_MONITOR Monitor
    );

#ifdef __cplusplus
}
#endif
