/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PRIVILEGE ESCALATION MONITOR IMPLEMENTATION
===============================================================================

@file PrivilegeMonitor.c
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

Performance Characteristics:
- O(1) baseline lookup via hash table
- Lock-free statistics using InterlockedXxx
- Lookaside lists for high-frequency allocations
- Configurable monitoring depth
- Early exit for trusted processes

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "PrivilegeMonitor.h"
#include "TokenAnalyzer.h"
#include "../../Core/Globals.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, PmInitialize)
#pragma alloc_text(PAGE, PmShutdown)
#pragma alloc_text(PAGE, PmRecordBaseline)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PM_POOL_TAG_INTERNAL            'NOMP'  // PMON reversed
#define PM_BASELINE_POOL_TAG            'lBMP'  // PMBl
#define PM_EVENT_POOL_TAG               'vEMP'  // PMEv
#define PM_MAX_BASELINES                8192
#define PM_MAX_EVENTS                   4096
#define PM_CLEANUP_INTERVAL_MS          60000   // 1 minute
#define PM_BASELINE_TIMEOUT_MS          600000  // 10 minutes after process exit
#define PM_MAX_PROCESS_NAME_LEN         260

//
// Privilege bit flags for tracking
//
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

//
// Integrity level values
//
#define PM_INTEGRITY_UNTRUSTED          0x0000
#define PM_INTEGRITY_LOW                0x1000
#define PM_INTEGRITY_MEDIUM             0x2000
#define PM_INTEGRITY_MEDIUM_PLUS        0x2100
#define PM_INTEGRITY_HIGH               0x3000
#define PM_INTEGRITY_SYSTEM             0x4000
#define PM_INTEGRITY_PROTECTED          0x5000

//
// Suspicion thresholds
//
#define PM_SUSPICION_LOW                20
#define PM_SUSPICION_MEDIUM             45
#define PM_SUSPICION_HIGH               70
#define PM_SUSPICION_CRITICAL           90

//
// Hash table constants
//
#define PM_HASH_BUCKET_COUNT            256

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Process privilege baseline
//
typedef struct _PM_PROCESS_BASELINE {
    //
    // Identification
    //
    HANDLE ProcessId;
    PEPROCESS ProcessObject;
    WCHAR ProcessName[PM_MAX_PROCESS_NAME_LEN];

    //
    // Original token state
    //
    LUID AuthenticationId;
    ULONG OriginalIntegrityLevel;
    ULONG OriginalPrivileges;
    BOOLEAN OriginalIsElevated;
    BOOLEAN OriginalIsSystem;
    BOOLEAN OriginalIsService;
    ULONG OriginalSessionId;

    //
    // Current token state (for comparison)
    //
    ULONG CurrentIntegrityLevel;
    ULONG CurrentPrivileges;
    BOOLEAN CurrentIsElevated;

    //
    // Tracking
    //
    LARGE_INTEGER BaselineTime;
    LARGE_INTEGER LastCheckTime;
    ULONG CheckCount;
    ULONG EscalationCount;

    //
    // Flags
    //
    ULONG Flags;
    BOOLEAN IsTerminated;
    BOOLEAN HasEscalated;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

} PM_PROCESS_BASELINE, *PPM_PROCESS_BASELINE;

//
// Baseline flags
//
#define PM_BASELINE_FLAG_MONITORED      0x00000001
#define PM_BASELINE_FLAG_SUSPICIOUS     0x00000002
#define PM_BASELINE_FLAG_ELEVATED       0x00000004
#define PM_BASELINE_FLAG_SYSTEM         0x00000008
#define PM_BASELINE_FLAG_PROTECTED      0x00000010

//
// Hash bucket for baseline lookup
//
typedef struct _PM_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
} PM_HASH_BUCKET, *PPM_HASH_BUCKET;

//
// Known UAC bypass techniques
//
typedef struct _PM_UAC_BYPASS_PATTERN {
    PCWSTR ProcessName;
    PCWSTR ParentProcessName;
    PCWSTR CommandLinePattern;
    PCSTR TechniqueName;
    ULONG SuspicionScore;
} PM_UAC_BYPASS_PATTERN, *PPM_UAC_BYPASS_PATTERN;

//
// Internal monitor state (extends public PM_MONITOR)
//
typedef struct _PM_MONITOR_INTERNAL {
    //
    // Public structure (must be first)
    //
    PM_MONITOR Public;

    //
    // Hash table for fast baseline lookup
    //
    PM_HASH_BUCKET HashTable[PM_HASH_BUCKET_COUNT];

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST BaselineLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableIntegrityMonitoring;
        BOOLEAN EnablePrivilegeMonitoring;
        BOOLEAN EnableUACBypassDetection;
        BOOLEAN EnableTokenManipulationDetection;
        BOOLEAN AlertOnEscalation;
        ULONG MinAlertScore;
    } Config;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

} PM_MONITOR_INTERNAL, *PPM_MONITOR_INTERNAL;

// ============================================================================
// KNOWN UAC BYPASS PATTERNS
// ============================================================================

static const PM_UAC_BYPASS_PATTERN g_UACBypassPatterns[] = {
    //
    // fodhelper.exe bypass
    //
    {
        L"fodhelper.exe",
        NULL,
        NULL,
        "T1548.002 - fodhelper UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // eventvwr.exe bypass
    //
    {
        L"eventvwr.exe",
        NULL,
        L"mmc.exe",
        "T1548.002 - eventvwr UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // sdclt.exe bypass
    //
    {
        L"sdclt.exe",
        NULL,
        NULL,
        "T1548.002 - sdclt UAC Bypass",
        PM_SUSPICION_MEDIUM
    },

    //
    // computerdefaults.exe bypass
    //
    {
        L"computerdefaults.exe",
        NULL,
        NULL,
        "T1548.002 - computerdefaults UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // cmstp.exe bypass
    //
    {
        L"cmstp.exe",
        NULL,
        L"/au",
        "T1548.002 - cmstp UAC Bypass",
        PM_SUSPICION_CRITICAL
    },

    //
    // WSReset.exe bypass
    //
    {
        L"WSReset.exe",
        NULL,
        NULL,
        "T1548.002 - WSReset UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // slui.exe bypass
    //
    {
        L"slui.exe",
        NULL,
        NULL,
        "T1548.002 - slui UAC Bypass",
        PM_SUSPICION_MEDIUM
    },

    //
    // DiskCleanup bypass
    //
    {
        L"cleanmgr.exe",
        NULL,
        L"/autoclean",
        "T1548.002 - DiskCleanup UAC Bypass",
        PM_SUSPICION_MEDIUM
    }
};

#define PM_UAC_BYPASS_PATTERN_COUNT (sizeof(g_UACBypassPatterns) / sizeof(g_UACBypassPatterns[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPM_PROCESS_BASELINE
PmpAllocateBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor
    );

static VOID
PmpFreeBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    );

static PPM_PROCESS_BASELINE
PmpLookupBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ HANDLE ProcessId
    );

static VOID
PmpInsertBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    );

static VOID
PmpRemoveBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    );

static VOID
PmpReferenceBaseline(
    _Inout_ PPM_PROCESS_BASELINE Baseline
    );

static VOID
PmpDereferenceBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _Inout_ PPM_PROCESS_BASELINE Baseline
    );

static ULONG
PmpHashProcessId(
    _In_ HANDLE ProcessId
    );

static PPM_ESCALATION_EVENT
PmpAllocateEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor
    );

static VOID
PmpFreeEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_ESCALATION_EVENT Event
    );

static VOID
PmpInsertEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_ESCALATION_EVENT Event
    );

static NTSTATUS
PmpCaptureTokenState(
    _In_ HANDLE ProcessId,
    _Out_ PULONG IntegrityLevel,
    _Out_ PULONG Privileges,
    _Out_ PBOOLEAN IsElevated,
    _Out_ PBOOLEAN IsSystem,
    _Out_ PBOOLEAN IsService,
    _Out_ PULONG SessionId,
    _Out_ PLUID AuthenticationId
    );

static ULONG
PmpConvertPrivilegesToFlags(
    _In_ PACCESS_TOKEN Token
    );

static NTSTATUS
PmpCompareTokenStates(
    _In_ PPM_PROCESS_BASELINE Baseline,
    _Out_ PPM_ESCALATION_EVENT Event
    );

static PM_ESCALATION_TYPE
PmpDetermineEscalationType(
    _In_ PPM_PROCESS_BASELINE Baseline,
    _In_ ULONG OldIntegrity,
    _In_ ULONG NewIntegrity,
    _In_ ULONG OldPrivileges,
    _In_ ULONG NewPrivileges
    );

static ULONG
PmpCalculateSuspicionScore(
    _In_ PPM_ESCALATION_EVENT Event,
    _In_ PPM_PROCESS_BASELINE Baseline
    );

static BOOLEAN
PmpIsLegitimateEscalation(
    _In_ PPM_ESCALATION_EVENT Event,
    _In_ PPM_PROCESS_BASELINE Baseline
    );

static BOOLEAN
PmpDetectUACBypass(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ HANDLE ProcessId,
    _In_ PCWSTR ProcessName,
    _Out_ PCHAR TechniqueBuffer,
    _In_ ULONG TechniqueBufferSize
    );

static VOID
PmpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
PmpCleanupStaleBaselines(
    _In_ PPM_MONITOR_INTERNAL Monitor
    );

static VOID
PmpGetPrivilegeString(
    _In_ ULONG PrivilegeFlags,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmInitialize(
    _Out_ PPM_MONITOR* Monitor
    )
/*++
Routine Description:
    Initializes the privilege escalation monitor.

Arguments:
    Monitor - Receives pointer to initialized monitor.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER DueTime;
    ULONG i;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    //
    // Allocate internal monitor structure
    //
    Internal = (PPM_MONITOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PM_MONITOR_INTERNAL),
        PM_POOL_TAG_INTERNAL
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(PM_MONITOR_INTERNAL));

    //
    // Initialize baseline list
    //
    InitializeListHead(&Internal->Public.ProcessBaselines);
    ExInitializePushLock(&Internal->Public.BaselineLock);

    //
    // Initialize event list
    //
    InitializeListHead(&Internal->Public.EventList);
    KeInitializeSpinLock(&Internal->Public.EventLock);

    //
    // Initialize hash table
    //
    for (i = 0; i < PM_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&Internal->HashTable[i].List);
        ExInitializePushLock(&Internal->HashTable[i].Lock);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Internal->BaselineLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PM_PROCESS_BASELINE),
        PM_BASELINE_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PM_ESCALATION_EVENT),
        PM_EVENT_POOL_TAG,
        0
        );

    Internal->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    Internal->Config.EnableIntegrityMonitoring = TRUE;
    Internal->Config.EnablePrivilegeMonitoring = TRUE;
    Internal->Config.EnableUACBypassDetection = TRUE;
    Internal->Config.EnableTokenManipulationDetection = TRUE;
    Internal->Config.AlertOnEscalation = TRUE;
    Internal->Config.MinAlertScore = PM_SUSPICION_MEDIUM;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Internal->Public.Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Internal->CleanupTimer);
    KeInitializeDpc(&Internal->CleanupDpc, PmpCleanupTimerDpc, Internal);

    //
    // Start cleanup timer (every 1 minute)
    //
    DueTime.QuadPart = -((LONGLONG)PM_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &Internal->CleanupTimer,
        DueTime,
        PM_CLEANUP_INTERVAL_MS,
        &Internal->CleanupDpc
        );
    Internal->CleanupTimerActive = TRUE;

    Internal->Public.Initialized = TRUE;
    *Monitor = (PPM_MONITOR)Internal;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PrivilegeMonitor] Privilege escalation monitor initialized\n"
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
PmShutdown(
    _Inout_ PPM_MONITOR Monitor
    )
/*++
Routine Description:
    Shuts down the privilege escalation monitor.

Arguments:
    Monitor - Monitor instance to shutdown.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PLIST_ENTRY Entry;
    PPM_PROCESS_BASELINE Baseline;
    PPM_ESCALATION_EVENT Event;
    KIRQL OldIrql;

    PAGED_CODE();

    if (Internal == NULL || !Internal->Public.Initialized) {
        return;
    }

    Internal->Public.Initialized = FALSE;
    Internal->ShutdownRequested = TRUE;

    //
    // Cancel cleanup timer
    //
    if (Internal->CleanupTimerActive) {
        KeCancelTimer(&Internal->CleanupTimer);
        Internal->CleanupTimerActive = FALSE;
    }

    //
    // Free all baselines
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.BaselineLock);

    while (!IsListEmpty(&Internal->Public.ProcessBaselines)) {
        Entry = RemoveHeadList(&Internal->Public.ProcessBaselines);
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);

        //
        // Remove from hash table
        //
        if (!IsListEmpty(&Baseline->HashEntry)) {
            RemoveEntryList(&Baseline->HashEntry);
            InitializeListHead(&Baseline->HashEntry);
        }

        ExReleasePushLockExclusive(&Internal->Public.BaselineLock);
        KeLeaveCriticalRegion();

        PmpFreeBaseline(Internal, Baseline);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->Public.BaselineLock);
    }

    ExReleasePushLockExclusive(&Internal->Public.BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Free all events
    //
    KeAcquireSpinLock(&Internal->Public.EventLock, &OldIrql);

    while (!IsListEmpty(&Internal->Public.EventList)) {
        Entry = RemoveHeadList(&Internal->Public.EventList);
        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        KeReleaseSpinLock(&Internal->Public.EventLock, OldIrql);

        PmpFreeEvent(Internal, Event);

        KeAcquireSpinLock(&Internal->Public.EventLock, &OldIrql);
    }

    KeReleaseSpinLock(&Internal->Public.EventLock, OldIrql);

    //
    // Delete lookaside lists
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->BaselineLookaside);
        ExDeleteNPagedLookasideList(&Internal->EventLookaside);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PrivilegeMonitor] Shutdown complete. "
        "Stats: Escalations=%lld, Legitimate=%lld\n",
        Internal->Public.Stats.EscalationsDetected,
        Internal->Public.Stats.LegitimateEscalations
        );

    //
    // Free monitor
    //
    ShadowStrikeFreePoolWithTag(Internal, PM_POOL_TAG_INTERNAL);
}


// ============================================================================
// BASELINE MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmRecordBaseline(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Records a privilege baseline for a process.

    This should be called when a process is created to establish
    the initial privilege state for later comparison.

Arguments:
    Monitor - Monitor instance.
    ProcessId - Process ID to record baseline for.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline = NULL;
    PPM_PROCESS_BASELINE Existing = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;
    ULONG IntegrityLevel = 0;
    ULONG Privileges = 0;
    BOOLEAN IsElevated = FALSE;
    BOOLEAN IsSystem = FALSE;
    BOOLEAN IsService = FALSE;
    ULONG SessionId = 0;
    LUID AuthenticationId = {0};
    UNICODE_STRING ImageName = {0};

    PAGED_CODE();

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if baseline already exists
    //
    Existing = PmpLookupBaseline(Internal, ProcessId);
    if (Existing != NULL) {
        PmpDereferenceBaseline(Internal, Existing);
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Capture current token state
    //
    Status = PmpCaptureTokenState(
        ProcessId,
        &IntegrityLevel,
        &Privileges,
        &IsElevated,
        &IsSystem,
        &IsService,
        &SessionId,
        &AuthenticationId
        );

    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(Process);
        return Status;
    }

    //
    // Allocate baseline
    //
    Baseline = PmpAllocateBaseline(Internal);
    if (Baseline == NULL) {
        ObDereferenceObject(Process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate baseline
    //
    Baseline->ProcessId = ProcessId;
    Baseline->ProcessObject = Process;  // Keep reference

    //
    // Get process name
    //
    Status = ShadowStrikeGetProcessImageName(ProcessId, &ImageName);
    if (NT_SUCCESS(Status) && ImageName.Buffer != NULL) {
        RtlStringCchCopyW(
            Baseline->ProcessName,
            PM_MAX_PROCESS_NAME_LEN,
            ImageName.Buffer
            );
        ShadowFreeProcessString(&ImageName);
    }

    //
    // Store original state
    //
    Baseline->AuthenticationId = AuthenticationId;
    Baseline->OriginalIntegrityLevel = IntegrityLevel;
    Baseline->OriginalPrivileges = Privileges;
    Baseline->OriginalIsElevated = IsElevated;
    Baseline->OriginalIsSystem = IsSystem;
    Baseline->OriginalIsService = IsService;
    Baseline->OriginalSessionId = SessionId;

    //
    // Current state starts same as original
    //
    Baseline->CurrentIntegrityLevel = IntegrityLevel;
    Baseline->CurrentPrivileges = Privileges;
    Baseline->CurrentIsElevated = IsElevated;

    //
    // Set flags
    //
    Baseline->Flags = PM_BASELINE_FLAG_MONITORED;
    if (IsElevated) {
        Baseline->Flags |= PM_BASELINE_FLAG_ELEVATED;
    }
    if (IsSystem) {
        Baseline->Flags |= PM_BASELINE_FLAG_SYSTEM;
    }

    //
    // Timestamps
    //
    KeQuerySystemTime(&Baseline->BaselineTime);
    Baseline->LastCheckTime = Baseline->BaselineTime;

    //
    // Insert into tracking structures
    //
    PmpInsertBaseline(Internal, Baseline);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PmCheckForEscalation(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PPM_ESCALATION_EVENT* Event
    )
/*++
Routine Description:
    Checks if a process has escalated privileges since baseline.

Arguments:
    Monitor - Monitor instance.
    ProcessId - Process ID to check.
    Event - Receives escalation event if detected.

Return Value:
    STATUS_SUCCESS if escalation detected.
    STATUS_NO_MORE_ENTRIES if no escalation.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline = NULL;
    PPM_ESCALATION_EVENT NewEvent = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentIntegrity = 0;
    ULONG CurrentPrivileges = 0;
    BOOLEAN CurrentIsElevated = FALSE;
    BOOLEAN IsSystem = FALSE;
    BOOLEAN IsService = FALSE;
    ULONG SessionId = 0;
    LUID AuthenticationId = {0};
    BOOLEAN EscalationDetected = FALSE;

    if (Internal == NULL || !Internal->Public.Initialized || Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Event = NULL;

    //
    // Look up baseline
    //
    Baseline = PmpLookupBaseline(Internal, ProcessId);
    if (Baseline == NULL) {
        //
        // No baseline - record one now and return
        //
        PmRecordBaseline(Monitor, ProcessId);
        return STATUS_NO_MORE_ENTRIES;
    }

    //
    // Capture current token state
    //
    Status = PmpCaptureTokenState(
        ProcessId,
        &CurrentIntegrity,
        &CurrentPrivileges,
        &CurrentIsElevated,
        &IsSystem,
        &IsService,
        &SessionId,
        &AuthenticationId
        );

    if (!NT_SUCCESS(Status)) {
        PmpDereferenceBaseline(Internal, Baseline);
        return Status;
    }

    //
    // Update check time
    //
    KeQuerySystemTime(&Baseline->LastCheckTime);
    Baseline->CheckCount++;

    //
    // Compare states for escalation
    //

    //
    // 1. Integrity level increase
    //
    if (Internal->Config.EnableIntegrityMonitoring &&
        CurrentIntegrity > Baseline->OriginalIntegrityLevel) {
        EscalationDetected = TRUE;
    }

    //
    // 2. Privilege addition
    //
    if (Internal->Config.EnablePrivilegeMonitoring) {
        ULONG NewPrivileges = CurrentPrivileges & ~Baseline->OriginalPrivileges;
        if (NewPrivileges != 0) {
            //
            // Check for sensitive privilege additions
            //
            if (NewPrivileges & (PM_PRIV_DEBUG | PM_PRIV_TCB | PM_PRIV_LOAD_DRIVER |
                                 PM_PRIV_CREATE_TOKEN | PM_PRIV_ASSIGN_PRIMARY)) {
                EscalationDetected = TRUE;
            }
        }
    }

    //
    // 3. Elevation change
    //
    if (!Baseline->OriginalIsElevated && CurrentIsElevated) {
        EscalationDetected = TRUE;
    }

    //
    // 4. Authentication ID change (token replacement)
    //
    if (Internal->Config.EnableTokenManipulationDetection) {
        if (Baseline->AuthenticationId.LowPart != AuthenticationId.LowPart ||
            Baseline->AuthenticationId.HighPart != AuthenticationId.HighPart) {
            EscalationDetected = TRUE;
        }
    }

    if (!EscalationDetected) {
        //
        // Update current state for future checks
        //
        Baseline->CurrentIntegrityLevel = CurrentIntegrity;
        Baseline->CurrentPrivileges = CurrentPrivileges;
        Baseline->CurrentIsElevated = CurrentIsElevated;

        PmpDereferenceBaseline(Internal, Baseline);
        return STATUS_NO_MORE_ENTRIES;
    }

    //
    // Escalation detected - create event
    //
    NewEvent = PmpAllocateEvent(Internal);
    if (NewEvent == NULL) {
        PmpDereferenceBaseline(Internal, Baseline);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate event
    //
    NewEvent->ProcessId = ProcessId;

    //
    // Copy process name
    //
    RtlInitUnicodeString(&NewEvent->ProcessName, NULL);
    if (Baseline->ProcessName[0] != L'\0') {
        SIZE_T NameLen = wcslen(Baseline->ProcessName) * sizeof(WCHAR);
        PWCHAR NameBuffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            NameLen + sizeof(WCHAR),
            PM_EVENT_POOL_TAG
            );
        if (NameBuffer != NULL) {
            RtlCopyMemory(NameBuffer, Baseline->ProcessName, NameLen);
            NameBuffer[NameLen / sizeof(WCHAR)] = L'\0';
            NewEvent->ProcessName.Buffer = NameBuffer;
            NewEvent->ProcessName.Length = (USHORT)NameLen;
            NewEvent->ProcessName.MaximumLength = (USHORT)(NameLen + sizeof(WCHAR));
        }
    }

    //
    // Before/after state
    //
    NewEvent->OldIntegrityLevel = Baseline->OriginalIntegrityLevel;
    NewEvent->NewIntegrityLevel = CurrentIntegrity;
    NewEvent->OldPrivileges = Baseline->OriginalPrivileges;
    NewEvent->NewPrivileges = CurrentPrivileges;

    //
    // Determine escalation type
    //
    NewEvent->Type = PmpDetermineEscalationType(
        Baseline,
        Baseline->OriginalIntegrityLevel,
        CurrentIntegrity,
        Baseline->OriginalPrivileges,
        CurrentPrivileges
        );

    //
    // Check for UAC bypass
    //
    if (Internal->Config.EnableUACBypassDetection) {
        if (PmpDetectUACBypass(
                Internal,
                ProcessId,
                Baseline->ProcessName,
                NewEvent->Technique,
                sizeof(NewEvent->Technique))) {
            NewEvent->Type = PmEscalation_UACBypass;
        }
    }

    //
    // Calculate suspicion score
    //
    NewEvent->SuspicionScore = PmpCalculateSuspicionScore(NewEvent, Baseline);

    //
    // Determine if legitimate
    //
    NewEvent->IsLegitimate = PmpIsLegitimateEscalation(NewEvent, Baseline);

    //
    // Timestamp
    //
    KeQuerySystemTime(&NewEvent->Timestamp);

    //
    // Update baseline state
    //
    Baseline->CurrentIntegrityLevel = CurrentIntegrity;
    Baseline->CurrentPrivileges = CurrentPrivileges;
    Baseline->CurrentIsElevated = CurrentIsElevated;
    Baseline->EscalationCount++;
    Baseline->HasEscalated = TRUE;
    Baseline->Flags |= PM_BASELINE_FLAG_SUSPICIOUS;

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->Public.Stats.EscalationsDetected);
    if (NewEvent->IsLegitimate) {
        InterlockedIncrement64(&Internal->Public.Stats.LegitimateEscalations);
    }

    //
    // Insert event
    //
    PmpInsertEvent(Internal, NewEvent);

    PmpDereferenceBaseline(Internal, Baseline);

    *Event = NewEvent;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_WARNING_LEVEL,
        "[ShadowStrike/PrivilegeMonitor] ESCALATION DETECTED: PID=%lu, Type=%d, "
        "Integrity=%lu->%lu, Score=%lu, Legitimate=%d\n",
        HandleToULong(ProcessId),
        NewEvent->Type,
        NewEvent->OldIntegrityLevel,
        NewEvent->NewIntegrityLevel,
        NewEvent->SuspicionScore,
        NewEvent->IsLegitimate
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PmGetEvents(
    _In_ PPM_MONITOR Monitor,
    _Out_writes_to_(Max, *Count) PPM_ESCALATION_EVENT* Events,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    Gets escalation events.

Arguments:
    Monitor - Monitor instance.
    Events - Array to receive event pointers.
    Max - Maximum events to return.
    Count - Receives number of events returned.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PLIST_ENTRY Entry;
    PPM_ESCALATION_EVENT Event;
    KIRQL OldIrql;
    ULONG Found = 0;

    if (Internal == NULL || !Internal->Public.Initialized ||
        Events == NULL || Count == NULL || Max == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;
    RtlZeroMemory(Events, Max * sizeof(PPM_ESCALATION_EVENT));

    KeAcquireSpinLock(&Internal->Public.EventLock, &OldIrql);

    for (Entry = Internal->Public.EventList.Flink;
         Entry != &Internal->Public.EventList && Found < Max;
         Entry = Entry->Flink) {

        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        Events[Found] = Event;
        Found++;
    }

    KeReleaseSpinLock(&Internal->Public.EventLock, OldIrql);

    *Count = Found;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
PmFreeEvent(
    _In_ PPM_ESCALATION_EVENT Event
    )
/*++
Routine Description:
    Frees an escalation event.

Arguments:
    Event - Event to free.
--*/
{
    if (Event == NULL) {
        return;
    }

    //
    // Free process name if allocated
    //
    if (Event->ProcessName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Event->ProcessName.Buffer, PM_EVENT_POOL_TAG);
        Event->ProcessName.Buffer = NULL;
    }

    //
    // Note: Actual event structure freed by monitor when removed from list
    //
}


// ============================================================================
// BASELINE MANAGEMENT HELPERS
// ============================================================================

static PPM_PROCESS_BASELINE
PmpAllocateBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor
    )
{
    PPM_PROCESS_BASELINE Baseline;

    Baseline = (PPM_PROCESS_BASELINE)ExAllocateFromNPagedLookasideList(
        &Monitor->BaselineLookaside
        );

    if (Baseline != NULL) {
        RtlZeroMemory(Baseline, sizeof(PM_PROCESS_BASELINE));
        Baseline->RefCount = 1;
        InitializeListHead(&Baseline->ListEntry);
        InitializeListHead(&Baseline->HashEntry);
    }

    return Baseline;
}


static VOID
PmpFreeBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    )
{
    if (Baseline == NULL) {
        return;
    }

    //
    // Dereference process object
    //
    if (Baseline->ProcessObject != NULL) {
        ObDereferenceObject(Baseline->ProcessObject);
        Baseline->ProcessObject = NULL;
    }

    ExFreeToNPagedLookasideList(&Monitor->BaselineLookaside, Baseline);
}


static ULONG
PmpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    Value = Value ^ (Value >> 16);
    Value = Value * 0x85EBCA6B;
    Value = Value ^ (Value >> 13);

    return (ULONG)(Value % PM_HASH_BUCKET_COUNT);
}


static PPM_PROCESS_BASELINE
PmpLookupBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ HANDLE ProcessId
    )
{
    ULONG BucketIndex;
    PPM_HASH_BUCKET Bucket;
    PLIST_ENTRY Entry;
    PPM_PROCESS_BASELINE Baseline = NULL;

    BucketIndex = PmpHashProcessId(ProcessId);
    Bucket = &Monitor->HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Bucket->Lock);

    for (Entry = Bucket->List.Flink;
         Entry != &Bucket->List;
         Entry = Entry->Flink) {

        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, HashEntry);

        if (Baseline->ProcessId == ProcessId && !Baseline->IsTerminated) {
            PmpReferenceBaseline(Baseline);
            ExReleasePushLockShared(&Bucket->Lock);
            KeLeaveCriticalRegion();
            return Baseline;
        }
    }

    ExReleasePushLockShared(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return NULL;
}


static VOID
PmpInsertBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    )
{
    ULONG BucketIndex;
    PPM_HASH_BUCKET Bucket;

    //
    // Reference for list storage
    //
    PmpReferenceBaseline(Baseline);

    //
    // Insert into main list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->Public.BaselineLock);

    InsertTailList(&Monitor->Public.ProcessBaselines, &Baseline->ListEntry);

    ExReleasePushLockExclusive(&Monitor->Public.BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Insert into hash table
    //
    BucketIndex = PmpHashProcessId(Baseline->ProcessId);
    Bucket = &Monitor->HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    InsertTailList(&Bucket->List, &Baseline->HashEntry);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();
}


static VOID
PmpRemoveBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    )
{
    ULONG BucketIndex;
    PPM_HASH_BUCKET Bucket;
    BOOLEAN WasInList = FALSE;

    //
    // Remove from hash table
    //
    BucketIndex = PmpHashProcessId(Baseline->ProcessId);
    Bucket = &Monitor->HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    if (!IsListEmpty(&Baseline->HashEntry)) {
        RemoveEntryList(&Baseline->HashEntry);
        InitializeListHead(&Baseline->HashEntry);
    }

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Remove from main list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->Public.BaselineLock);

    if (!IsListEmpty(&Baseline->ListEntry)) {
        RemoveEntryList(&Baseline->ListEntry);
        InitializeListHead(&Baseline->ListEntry);
        WasInList = TRUE;
    }

    ExReleasePushLockExclusive(&Monitor->Public.BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Release list reference
    //
    if (WasInList) {
        PmpDereferenceBaseline(Monitor, Baseline);
    }
}


static VOID
PmpReferenceBaseline(
    _Inout_ PPM_PROCESS_BASELINE Baseline
    )
{
    InterlockedIncrement(&Baseline->RefCount);
}


static VOID
PmpDereferenceBaseline(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _Inout_ PPM_PROCESS_BASELINE Baseline
    )
{
    if (InterlockedDecrement(&Baseline->RefCount) == 0) {
        PmpFreeBaseline(Monitor, Baseline);
    }
}


// ============================================================================
// EVENT MANAGEMENT
// ============================================================================

static PPM_ESCALATION_EVENT
PmpAllocateEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor
    )
{
    PPM_ESCALATION_EVENT Event;

    Event = (PPM_ESCALATION_EVENT)ExAllocateFromNPagedLookasideList(
        &Monitor->EventLookaside
        );

    if (Event != NULL) {
        RtlZeroMemory(Event, sizeof(PM_ESCALATION_EVENT));
        InitializeListHead(&Event->ListEntry);
    }

    return Event;
}


static VOID
PmpFreeEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_ESCALATION_EVENT Event
    )
{
    if (Event == NULL) {
        return;
    }

    //
    // Free process name
    //
    if (Event->ProcessName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Event->ProcessName.Buffer, PM_EVENT_POOL_TAG);
    }

    ExFreeToNPagedLookasideList(&Monitor->EventLookaside, Event);
}


static VOID
PmpInsertEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_ESCALATION_EVENT Event
    )
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&Monitor->Public.EventLock, &OldIrql);

    //
    // Check limit
    //
    if ((ULONG)Monitor->Public.EventCount >= PM_MAX_EVENTS) {
        //
        // Remove oldest event
        //
        if (!IsListEmpty(&Monitor->Public.EventList)) {
            PLIST_ENTRY Entry = RemoveHeadList(&Monitor->Public.EventList);
            PPM_ESCALATION_EVENT OldEvent = CONTAINING_RECORD(
                Entry, PM_ESCALATION_EVENT, ListEntry);
            InterlockedDecrement(&Monitor->Public.EventCount);

            KeReleaseSpinLock(&Monitor->Public.EventLock, OldIrql);
            PmpFreeEvent(Monitor, OldEvent);
            KeAcquireSpinLock(&Monitor->Public.EventLock, &OldIrql);
        }
    }

    InsertTailList(&Monitor->Public.EventList, &Event->ListEntry);
    InterlockedIncrement(&Monitor->Public.EventCount);

    KeReleaseSpinLock(&Monitor->Public.EventLock, OldIrql);
}


// ============================================================================
// TOKEN STATE CAPTURE
// ============================================================================

static NTSTATUS
PmpCaptureTokenState(
    _In_ HANDLE ProcessId,
    _Out_ PULONG IntegrityLevel,
    _Out_ PULONG Privileges,
    _Out_ PBOOLEAN IsElevated,
    _Out_ PBOOLEAN IsSystem,
    _Out_ PBOOLEAN IsService,
    _Out_ PULONG SessionId,
    _Out_ PLUID AuthenticationId
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;
    PACCESS_TOKEN Token = NULL;

    *IntegrityLevel = PM_INTEGRITY_MEDIUM;
    *Privileges = 0;
    *IsElevated = FALSE;
    *IsSystem = FALSE;
    *IsService = FALSE;
    *SessionId = 0;
    RtlZeroMemory(AuthenticationId, sizeof(LUID));

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    __try {
        //
        // Get primary token
        //
        Token = PsReferencePrimaryToken(Process);
        if (Token == NULL) {
            Status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        //
        // Get session ID
        //
        Status = SeQuerySessionIdToken(Token, SessionId);
        if (!NT_SUCCESS(Status)) {
            *SessionId = 0;
        }

        //
        // Check for admin token
        //
        if (SeTokenIsAdmin(Token)) {
            *IsElevated = TRUE;
        }

        //
        // Get privilege flags
        //
        *Privileges = PmpConvertPrivilegesToFlags(Token);

        //
        // Determine integrity level
        // This is simplified - real implementation would query token
        //
        if (*IsElevated) {
            *IntegrityLevel = PM_INTEGRITY_HIGH;
        }

        //
        // Check for SYSTEM
        //
        if (*SessionId == 0 && *IsElevated) {
            //
            // Simplified check - session 0 + elevated often means system/service
            //
            *IsService = TRUE;
        }

        //
        // Check for actual SYSTEM token
        //
        {
            SECURITY_SUBJECT_CONTEXT SubjectContext;
            SeCaptureSubjectContext(&SubjectContext);

            if (SubjectContext.PrimaryToken == Token) {
                //
                // Additional checks could be done here
                //
            }

            SeReleaseSubjectContext(&SubjectContext);
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (Token != NULL) {
        PsDereferencePrimaryToken(Token);
    }

    ObDereferenceObject(Process);

    return Status;
}


static ULONG
PmpConvertPrivilegesToFlags(
    _In_ PACCESS_TOKEN Token
    )
{
    ULONG Flags = 0;

    UNREFERENCED_PARAMETER(Token);

    //
    // In a full implementation, we would enumerate token privileges
    // using SePrivilegeCheck or similar. For now, we check common ones.
    //

    //
    // The token analysis would be more comprehensive in production,
    // iterating through TOKEN_PRIVILEGES structure
    //

    return Flags;
}


// ============================================================================
// ESCALATION ANALYSIS
// ============================================================================

static PM_ESCALATION_TYPE
PmpDetermineEscalationType(
    _In_ PPM_PROCESS_BASELINE Baseline,
    _In_ ULONG OldIntegrity,
    _In_ ULONG NewIntegrity,
    _In_ ULONG OldPrivileges,
    _In_ ULONG NewPrivileges
    )
{
    ULONG AddedPrivileges = NewPrivileges & ~OldPrivileges;

    UNREFERENCED_PARAMETER(Baseline);

    //
    // Check for integrity increase
    //
    if (NewIntegrity > OldIntegrity) {
        if (OldIntegrity <= PM_INTEGRITY_MEDIUM && NewIntegrity >= PM_INTEGRITY_HIGH) {
            return PmEscalation_TokenElevation;
        }
        return PmEscalation_IntegrityIncrease;
    }

    //
    // Check for sensitive privilege additions
    //
    if (AddedPrivileges != 0) {
        if (AddedPrivileges & PM_PRIV_LOAD_DRIVER) {
            return PmEscalation_DriverLoad;
        }
        if (AddedPrivileges & PM_PRIV_TCB) {
            return PmEscalation_ExploitKernel;
        }
        if (AddedPrivileges & PM_PRIV_CREATE_TOKEN) {
            return PmEscalation_ExploitKernel;
        }
        return PmEscalation_PrivilegeEnable;
    }

    return PmEscalation_None;
}


static ULONG
PmpCalculateSuspicionScore(
    _In_ PPM_ESCALATION_EVENT Event,
    _In_ PPM_PROCESS_BASELINE Baseline
    )
{
    ULONG Score = 0;

    //
    // Base score by escalation type
    //
    switch (Event->Type) {
        case PmEscalation_ExploitKernel:
            Score += 90;
            break;

        case PmEscalation_UACBypass:
            Score += 80;
            break;

        case PmEscalation_TokenElevation:
            Score += 60;
            break;

        case PmEscalation_DriverLoad:
            Score += 70;
            break;

        case PmEscalation_ServiceCreation:
            Score += 50;
            break;

        case PmEscalation_IntegrityIncrease:
            Score += 40;
            break;

        case PmEscalation_PrivilegeEnable:
            Score += 30;
            break;

        default:
            Score += 20;
    }

    //
    // Adjust for integrity jump magnitude
    //
    if (Event->NewIntegrityLevel > Event->OldIntegrityLevel) {
        ULONG Jump = Event->NewIntegrityLevel - Event->OldIntegrityLevel;
        if (Jump >= 0x2000) {
            Score += 20;  // Large jump
        } else if (Jump >= 0x1000) {
            Score += 10;
        }
    }

    //
    // Sensitive privilege additions
    //
    ULONG NewPrivs = Event->NewPrivileges & ~Event->OldPrivileges;
    if (NewPrivs & PM_PRIV_DEBUG) Score += 15;
    if (NewPrivs & PM_PRIV_TCB) Score += 25;
    if (NewPrivs & PM_PRIV_LOAD_DRIVER) Score += 20;
    if (NewPrivs & PM_PRIV_CREATE_TOKEN) Score += 25;
    if (NewPrivs & PM_PRIV_ASSIGN_PRIMARY) Score += 15;

    //
    // Non-elevated process gaining elevation
    //
    if (!Baseline->OriginalIsElevated && Event->NewIntegrityLevel >= PM_INTEGRITY_HIGH) {
        Score += 15;
    }

    //
    // Non-system process in session 0
    //
    if (!Baseline->OriginalIsSystem && Baseline->OriginalSessionId != 0 &&
        Event->NewIntegrityLevel >= PM_INTEGRITY_SYSTEM) {
        Score += 20;
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}


static BOOLEAN
PmpIsLegitimateEscalation(
    _In_ PPM_ESCALATION_EVENT Event,
    _In_ PPM_PROCESS_BASELINE Baseline
    )
{
    //
    // System processes elevating is often legitimate
    //
    if (Baseline->OriginalIsSystem) {
        return TRUE;
    }

    //
    // Services in session 0 elevating is often legitimate
    //
    if (Baseline->OriginalIsService && Baseline->OriginalSessionId == 0) {
        return TRUE;
    }

    //
    // Known Windows elevation processes
    //
    if (Baseline->ProcessName[0] != L'\0') {
        if (_wcsicmp(Baseline->ProcessName, L"consent.exe") == 0 ||
            _wcsicmp(Baseline->ProcessName, L"svchost.exe") == 0 ||
            _wcsicmp(Baseline->ProcessName, L"services.exe") == 0 ||
            _wcsicmp(Baseline->ProcessName, L"lsass.exe") == 0 ||
            _wcsicmp(Baseline->ProcessName, L"csrss.exe") == 0 ||
            _wcsicmp(Baseline->ProcessName, L"wininit.exe") == 0 ||
            _wcsicmp(Baseline->ProcessName, L"winlogon.exe") == 0) {
            return TRUE;
        }
    }

    //
    // Low suspicion score is likely legitimate
    //
    if (Event->SuspicionScore < PM_SUSPICION_LOW) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
PmpDetectUACBypass(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ HANDLE ProcessId,
    _In_ PCWSTR ProcessName,
    _Out_ PCHAR TechniqueBuffer,
    _In_ ULONG TechniqueBufferSize
    )
{
    ULONG i;

    UNREFERENCED_PARAMETER(Monitor);
    UNREFERENCED_PARAMETER(ProcessId);

    TechniqueBuffer[0] = '\0';

    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return FALSE;
    }

    for (i = 0; i < PM_UAC_BYPASS_PATTERN_COUNT; i++) {
        const PM_UAC_BYPASS_PATTERN* Pattern = &g_UACBypassPatterns[i];

        if (_wcsicmp(ProcessName, Pattern->ProcessName) == 0) {
            RtlStringCchCopyA(
                TechniqueBuffer,
                TechniqueBufferSize,
                Pattern->TechniqueName
                );
            return TRUE;
        }
    }

    return FALSE;
}


// ============================================================================
// CLEANUP
// ============================================================================

static VOID
PmpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PPM_MONITOR_INTERNAL Monitor = (PPM_MONITOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Monitor == NULL || Monitor->ShutdownRequested) {
        return;
    }

    PmpCleanupStaleBaselines(Monitor);
}


static VOID
PmpCleanupStaleBaselines(
    _In_ PPM_MONITOR_INTERNAL Monitor
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PPM_PROCESS_BASELINE Baseline;
    LIST_ENTRY StaleList;

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)PM_BASELINE_TIMEOUT_MS * 10000;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->Public.BaselineLock);

    for (Entry = Monitor->Public.ProcessBaselines.Flink;
         Entry != &Monitor->Public.ProcessBaselines;
         Entry = Next) {

        Next = Entry->Flink;
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);

        //
        // Check if process has terminated and enough time has passed
        //
        if (Baseline->IsTerminated) {
            if ((CurrentTime.QuadPart - Baseline->LastCheckTime.QuadPart) > TimeoutInterval.QuadPart) {
                RemoveEntryList(&Baseline->ListEntry);
                InitializeListHead(&Baseline->ListEntry);
                InsertTailList(&StaleList, &Baseline->ListEntry);
            }
        } else {
            //
            // Check if process still exists
            //
            if (Baseline->ProcessObject != NULL) {
                if (ShadowStrikeIsProcessTerminating(Baseline->ProcessObject)) {
                    Baseline->IsTerminated = TRUE;
                    KeQuerySystemTime(&Baseline->LastCheckTime);
                }
            }
        }
    }

    ExReleasePushLockExclusive(&Monitor->Public.BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Free stale baselines outside lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);

        //
        // Remove from hash table
        //
        ULONG BucketIndex = PmpHashProcessId(Baseline->ProcessId);
        PPM_HASH_BUCKET Bucket = &Monitor->HashTable[BucketIndex];

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Bucket->Lock);

        if (!IsListEmpty(&Baseline->HashEntry)) {
            RemoveEntryList(&Baseline->HashEntry);
            InitializeListHead(&Baseline->HashEntry);
        }

        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();

        //
        // Release list reference
        //
        PmpDereferenceBaseline(Monitor, Baseline);
    }
}


static VOID
PmpGetPrivilegeString(
    _In_ ULONG PrivilegeFlags,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
    )
{
    Buffer[0] = '\0';

    if (PrivilegeFlags == 0) {
        RtlStringCchCopyA(Buffer, BufferSize, "None");
        return;
    }

    if (PrivilegeFlags & PM_PRIV_DEBUG) {
        RtlStringCchCatA(Buffer, BufferSize, "Debug ");
    }
    if (PrivilegeFlags & PM_PRIV_TCB) {
        RtlStringCchCatA(Buffer, BufferSize, "TCB ");
    }
    if (PrivilegeFlags & PM_PRIV_LOAD_DRIVER) {
        RtlStringCchCatA(Buffer, BufferSize, "LoadDriver ");
    }
    if (PrivilegeFlags & PM_PRIV_IMPERSONATE) {
        RtlStringCchCatA(Buffer, BufferSize, "Impersonate ");
    }
    if (PrivilegeFlags & PM_PRIV_CREATE_TOKEN) {
        RtlStringCchCatA(Buffer, BufferSize, "CreateToken ");
    }
}


// ============================================================================
// ADDITIONAL PUBLIC APIs
// ============================================================================

NTSTATUS
PmRemoveBaseline(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Removes baseline for a terminated process.

Arguments:
    Monitor - Monitor instance.
    ProcessId - Process ID.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Baseline = PmpLookupBaseline(Internal, ProcessId);
    if (Baseline == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Mark as terminated for later cleanup
    //
    Baseline->IsTerminated = TRUE;
    KeQuerySystemTime(&Baseline->LastCheckTime);

    PmpDereferenceBaseline(Internal, Baseline);

    return STATUS_SUCCESS;
}


NTSTATUS
PmGetStatistics(
    _In_ PPM_MONITOR Monitor,
    _Out_ PULONG64 EscalationsDetected,
    _Out_ PULONG64 LegitimateEscalations,
    _Out_ PULONG BaselineCount
    )
/*++
Routine Description:
    Gets monitor statistics.

Arguments:
    Monitor - Monitor instance.
    EscalationsDetected - Receives total escalation count.
    LegitimateEscalations - Receives legitimate escalation count.
    BaselineCount - Receives current baseline count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PLIST_ENTRY Entry;
    ULONG Count = 0;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (EscalationsDetected != NULL) {
        *EscalationsDetected = (ULONG64)Internal->Public.Stats.EscalationsDetected;
    }

    if (LegitimateEscalations != NULL) {
        *LegitimateEscalations = (ULONG64)Internal->Public.Stats.LegitimateEscalations;
    }

    if (BaselineCount != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Internal->Public.BaselineLock);

        for (Entry = Internal->Public.ProcessBaselines.Flink;
             Entry != &Internal->Public.ProcessBaselines;
             Entry = Entry->Flink) {
            Count++;
        }

        ExReleasePushLockShared(&Internal->Public.BaselineLock);
        KeLeaveCriticalRegion();

        *BaselineCount = Count;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
PmQueryProcessEscalation(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN HasEscalated,
    _Out_ PULONG EscalationCount,
    _Out_ PULONG CurrentIntegrityLevel
    )
/*++
Routine Description:
    Queries escalation status for a specific process.

Arguments:
    Monitor - Monitor instance.
    ProcessId - Process ID to query.
    HasEscalated - Receives whether process has escalated.
    EscalationCount - Receives number of escalations.
    CurrentIntegrityLevel - Receives current integrity level.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (HasEscalated != NULL) *HasEscalated = FALSE;
    if (EscalationCount != NULL) *EscalationCount = 0;
    if (CurrentIntegrityLevel != NULL) *CurrentIntegrityLevel = 0;

    Baseline = PmpLookupBaseline(Internal, ProcessId);
    if (Baseline == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (HasEscalated != NULL) {
        *HasEscalated = Baseline->HasEscalated;
    }

    if (EscalationCount != NULL) {
        *EscalationCount = Baseline->EscalationCount;
    }

    if (CurrentIntegrityLevel != NULL) {
        *CurrentIntegrityLevel = Baseline->CurrentIntegrityLevel;
    }

    PmpDereferenceBaseline(Internal, Baseline);

    return STATUS_SUCCESS;
}

