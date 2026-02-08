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

SECURITY FIXES APPLIED (v3.0.0):
- Fixed DPC IRQL violation using work item for cleanup
- Implemented actual privilege enumeration from token
- Fixed race conditions in event management
- Added proper shutdown synchronization with DPC flush
- Implemented reference counting for events
- Fixed integrity level detection using actual token query
- Added baseline count limits
- Fixed lock ordering for deadlock prevention
- Replaced unsafe string functions
- Added monitor validation and self-protection

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "PrivilegeMonitor.h"
#include "../../Core/Globals.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, PmInitialize)
#pragma alloc_text(PAGE, PmShutdown)
#pragma alloc_text(PAGE, PmRecordBaseline)
#pragma alloc_text(PAGE, PmRemoveBaseline)
#pragma alloc_text(PAGE, PmMarkProcessTerminated)
#pragma alloc_text(PAGE, PmCheckForEscalation)
#pragma alloc_text(PAGE, PmQueryProcessEscalation)
#pragma alloc_text(PAGE, PmGetConfiguration)
#pragma alloc_text(PAGE, PmSetConfiguration)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PM_CLEANUP_INTERVAL_MS          60000   // 1 minute
#define PM_BASELINE_TIMEOUT_MS          600000  // 10 minutes after process exit
#define PM_HASH_BUCKET_COUNT            256
#define PM_MONITOR_SIGNATURE            0x4D4F4E50  // 'PMON'
#define PM_MONITOR_SIGNATURE_DEAD       0x44454144  // 'DEAD'

//
// Privilege LUID values (from winnt.h)
//
#define SE_CREATE_TOKEN_PRIVILEGE           2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     3
#define SE_LOCK_MEMORY_PRIVILEGE            4
#define SE_INCREASE_QUOTA_PRIVILEGE         5
#define SE_TCB_PRIVILEGE                    7
#define SE_SECURITY_PRIVILEGE               8
#define SE_TAKE_OWNERSHIP_PRIVILEGE         9
#define SE_LOAD_DRIVER_PRIVILEGE            10
#define SE_SYSTEM_PROFILE_PRIVILEGE         11
#define SE_SYSTEMTIME_PRIVILEGE             12
#define SE_BACKUP_PRIVILEGE                 17
#define SE_RESTORE_PRIVILEGE                18
#define SE_SHUTDOWN_PRIVILEGE               19
#define SE_DEBUG_PRIVILEGE                  20
#define SE_AUDIT_PRIVILEGE                  21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     22
#define SE_IMPERSONATE_PRIVILEGE            29
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_CREATE_PAGEFILE_PRIVILEGE        15
#define SE_INCREASE_BASE_PRIORITY_PRIVILEGE 14

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
    HANDLE ParentProcessId;
    WCHAR ProcessName[PM_MAX_PROCESS_NAME_LEN];
    WCHAR ParentProcessName[PM_MAX_PROCESS_NAME_LEN];

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
    ULONG CurrentSessionId;
    LUID CurrentAuthenticationId;

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
// Work item context for cleanup
//
typedef struct _PM_CLEANUP_WORK_CONTEXT {
    PIO_WORKITEM WorkItem;
    struct _PM_MONITOR_INTERNAL* Monitor;
} PM_CLEANUP_WORK_CONTEXT, *PPM_CLEANUP_WORK_CONTEXT;

//
// Internal monitor state
//
typedef struct _PM_MONITOR_INTERNAL {
    //
    // Validation signature (for self-protection)
    //
    ULONG Signature;

    //
    // Initialization state
    //
    BOOLEAN Initialized;
    volatile BOOLEAN ShutdownRequested;

    //
    // Process baseline tracking
    //
    LIST_ENTRY ProcessBaselines;
    EX_PUSH_LOCK BaselineLock;
    volatile LONG BaselineCount;

    //
    // Hash table for fast baseline lookup
    //
    PM_HASH_BUCKET HashTable[PM_HASH_BUCKET_COUNT];

    //
    // Event tracking
    //
    LIST_ENTRY EventList;
    KSPIN_LOCK EventLock;
    volatile LONG EventCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST BaselineLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer and work item
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    PIO_WORKITEM CleanupWorkItem;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN CleanupTimerActive;
    volatile LONG CleanupInProgress;

    //
    // Configuration
    //
    PM_CONFIG Config;

    //
    // Statistics
    //
    PM_STATISTICS Stats;

    //
    // Configuration lock
    //
    EX_PUSH_LOCK ConfigLock;

} PM_MONITOR_INTERNAL, *PPM_MONITOR_INTERNAL;

// ============================================================================
// KNOWN UAC BYPASS PATTERNS
// ============================================================================

static const PM_UAC_BYPASS_PATTERN g_UACBypassPatterns[] = {
    //
    // fodhelper.exe bypass - auto-elevates, abused via registry hijack
    //
    {
        L"fodhelper.exe",
        L"explorer.exe",
        NULL,
        "T1548.002 - fodhelper UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // eventvwr.exe bypass - mmc.exe spawned with high integrity
    //
    {
        L"eventvwr.exe",
        L"explorer.exe",
        NULL,
        "T1548.002 - eventvwr UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // sdclt.exe bypass - backup and restore center
    //
    {
        L"sdclt.exe",
        L"explorer.exe",
        NULL,
        "T1548.002 - sdclt UAC Bypass",
        PM_SUSPICION_MEDIUM
    },

    //
    // computerdefaults.exe bypass
    //
    {
        L"computerdefaults.exe",
        L"explorer.exe",
        NULL,
        "T1548.002 - computerdefaults UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // cmstp.exe bypass - Connection Manager service profile
    //
    {
        L"cmstp.exe",
        NULL,
        L"/au",
        "T1548.002 - cmstp UAC Bypass",
        PM_SUSPICION_CRITICAL
    },

    //
    // WSReset.exe bypass - Windows Store reset
    //
    {
        L"WSReset.exe",
        L"explorer.exe",
        NULL,
        "T1548.002 - WSReset UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // slui.exe bypass - Software Licensing UI
    //
    {
        L"slui.exe",
        L"explorer.exe",
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
    },

    //
    // SilentCleanup scheduled task bypass
    //
    {
        L"cleanmgr.exe",
        L"svchost.exe",
        NULL,
        "T1548.002 - SilentCleanup UAC Bypass",
        PM_SUSPICION_HIGH
    },

    //
    // msconfig bypass
    //
    {
        L"msconfig.exe",
        L"explorer.exe",
        NULL,
        "T1548.002 - msconfig UAC Bypass",
        PM_SUSPICION_MEDIUM
    }
};

#define PM_UAC_BYPASS_PATTERN_COUNT (sizeof(g_UACBypassPatterns) / sizeof(g_UACBypassPatterns[0]))

//
// Known legitimate elevation processes
//
static const PCWSTR g_LegitimateElevationProcesses[] = {
    L"consent.exe",
    L"svchost.exe",
    L"services.exe",
    L"lsass.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"smss.exe",
    L"System",
    L"dwm.exe",
    L"taskhostw.exe",
    L"RuntimeBroker.exe",
    L"sihost.exe",
    L"fontdrvhost.exe",
    L"WmiPrvSE.exe"
};

#define PM_LEGITIMATE_PROCESS_COUNT (sizeof(g_LegitimateElevationProcesses) / sizeof(g_LegitimateElevationProcesses[0]))

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
PmpRemoveBaselineInternal(
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
PmpFreeEventInternal(
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

static ULONG
PmpGetTokenIntegrityLevel(
    _In_ PACCESS_TOKEN Token
    );

static PM_ESCALATION_TYPE
PmpDetermineEscalationType(
    _In_ PPM_PROCESS_BASELINE Baseline,
    _In_ ULONG OldIntegrity,
    _In_ ULONG NewIntegrity,
    _In_ ULONG OldPrivileges,
    _In_ ULONG NewPrivileges,
    _In_ ULONG OldSessionId,
    _In_ ULONG NewSessionId,
    _In_ PLUID OldAuthId,
    _In_ PLUID NewAuthId
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
    _In_ PPM_PROCESS_BASELINE Baseline,
    _Out_writes_bytes_(TechniqueBufferSize) PCHAR TechniqueBuffer,
    _In_ ULONG TechniqueBufferSize,
    _Out_ PULONG PatternScore
    );

static KDEFERRED_ROUTINE PmpCleanupTimerDpc;

IO_WORKITEM_ROUTINE PmpCleanupWorkRoutine;

static VOID
PmpCleanupStaleBaselines(
    _In_ PPM_MONITOR_INTERNAL Monitor
    );

static BOOLEAN
PmpCompareUnicodeStringInsensitive(
    _In_ PCWSTR String1,
    _In_ PCWSTR String2
    );

static BOOLEAN
PmpIsValidMonitorInternal(
    _In_opt_ PPM_MONITOR_INTERNAL Monitor
    );

// ============================================================================
// MONITOR VALIDATION
// ============================================================================

static BOOLEAN
PmpIsValidMonitorInternal(
    _In_opt_ PPM_MONITOR_INTERNAL Monitor
    )
{
    if (Monitor == NULL) {
        return FALSE;
    }

    __try {
        if (Monitor->Signature != PM_MONITOR_SIGNATURE) {
            return FALSE;
        }
        if (!Monitor->Initialized) {
            return FALSE;
        }
        if (Monitor->ShutdownRequested) {
            return FALSE;
        }
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}


_Use_decl_annotations_
BOOLEAN
PmIsValidMonitor(
    _In_opt_ PPM_MONITOR Monitor
    )
{
    return PmpIsValidMonitorInternal((PPM_MONITOR_INTERNAL)Monitor);
}

// ============================================================================
// STRING COMPARISON (IRQL-SAFE)
// ============================================================================

static BOOLEAN
PmpCompareUnicodeStringInsensitive(
    _In_ PCWSTR String1,
    _In_ PCWSTR String2
    )
/*++
Routine Description:
    Compares two null-terminated wide strings case-insensitively.
    Safe for use at any IRQL as it doesn't use RtlCompareUnicodeString.

Arguments:
    String1 - First string.
    String2 - Second string.

Return Value:
    TRUE if strings are equal (case-insensitive).
--*/
{
    WCHAR c1, c2;

    if (String1 == NULL || String2 == NULL) {
        return (String1 == String2);
    }

    while (*String1 != L'\0' && *String2 != L'\0') {
        c1 = *String1;
        c2 = *String2;

        //
        // Convert to uppercase for comparison
        //
        if (c1 >= L'a' && c1 <= L'z') {
            c1 = c1 - L'a' + L'A';
        }
        if (c2 >= L'a' && c2 <= L'z') {
            c2 = c2 - L'a' + L'A';
        }

        if (c1 != c2) {
            return FALSE;
        }

        String1++;
        String2++;
    }

    return (*String1 == L'\0' && *String2 == L'\0');
}

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
    // Allocate internal monitor structure from NonPaged pool
    //
    Internal = (PPM_MONITOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PM_MONITOR_INTERNAL),
        PM_POOL_TAG
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(PM_MONITOR_INTERNAL));

    //
    // Set signature for validation
    //
    Internal->Signature = PM_MONITOR_SIGNATURE;

    //
    // Initialize baseline list and lock
    //
    InitializeListHead(&Internal->ProcessBaselines);
    ExInitializePushLock(&Internal->BaselineLock);

    //
    // Initialize event list and lock
    //
    InitializeListHead(&Internal->EventList);
    KeInitializeSpinLock(&Internal->EventLock);

    //
    // Initialize hash table
    // LOCK ORDERING: Always acquire hash bucket lock AFTER baseline lock
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
    // Initialize configuration lock
    //
    ExInitializePushLock(&Internal->ConfigLock);

    //
    // Initialize default configuration
    //
    Internal->Config.EnableIntegrityMonitoring = TRUE;
    Internal->Config.EnablePrivilegeMonitoring = TRUE;
    Internal->Config.EnableUACBypassDetection = TRUE;
    Internal->Config.EnableTokenManipulationDetection = TRUE;
    Internal->Config.EnableCrossSessionDetection = TRUE;
    Internal->Config.AlertOnEscalation = TRUE;
    Internal->Config.BlockHighRiskEscalation = FALSE;
    Internal->Config.MinAlertScore = PM_SUSPICION_MEDIUM;
    Internal->Config.BlockThresholdScore = PM_SUSPICION_CRITICAL;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Internal->Stats.StartTime);

    //
    // Get device object for work item (use global if available)
    //
    Internal->DeviceObject = ShadowStrikeGetDeviceObject();
    if (Internal->DeviceObject == NULL) {
        //
        // Cannot create work items without device object
        // Fall back to not using timer-based cleanup
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/PrivilegeMonitor] No device object available, "
            "timer-based cleanup disabled\n"
            );
    } else {
        //
        // Allocate cleanup work item
        //
        Internal->CleanupWorkItem = IoAllocateWorkItem(Internal->DeviceObject);
        if (Internal->CleanupWorkItem == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        //
        // Initialize cleanup timer and DPC
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
    }

    Internal->Initialized = TRUE;
    *Monitor = (PPM_MONITOR)Internal;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PrivilegeMonitor] Privilege escalation monitor initialized (v3.0.0)\n"
        );

    return STATUS_SUCCESS;

Cleanup:
    if (Internal != NULL) {
        if (Internal->LookasideInitialized) {
            ExDeleteNPagedLookasideList(&Internal->BaselineLookaside);
            ExDeleteNPagedLookasideList(&Internal->EventLookaside);
        }
        Internal->Signature = PM_MONITOR_SIGNATURE_DEAD;
        ShadowStrikeFreePoolWithTag(Internal, PM_POOL_TAG);
    }

    return Status;
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
    LIST_ENTRY BaselinesToFree;
    LIST_ENTRY EventsToFree;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal)) {
        return;
    }

    //
    // Mark as shutting down
    //
    Internal->Initialized = FALSE;
    Internal->ShutdownRequested = TRUE;

    //
    // Cancel cleanup timer and WAIT for DPC completion
    //
    if (Internal->CleanupTimerActive) {
        KeCancelTimer(&Internal->CleanupTimer);

        //
        // CRITICAL: Wait for any running DPC to complete
        //
        KeFlushQueuedDpcs();

        //
        // Wait for cleanup work item to complete if in progress
        //
        while (InterlockedCompareExchange(&Internal->CleanupInProgress, 0, 0) != 0) {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10000; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        }

        Internal->CleanupTimerActive = FALSE;
    }

    //
    // Free cleanup work item
    //
    if (Internal->CleanupWorkItem != NULL) {
        IoFreeWorkItem(Internal->CleanupWorkItem);
        Internal->CleanupWorkItem = NULL;
    }

    //
    // Collect all baselines under lock, then free outside lock
    //
    InitializeListHead(&BaselinesToFree);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->BaselineLock);

    while (!IsListEmpty(&Internal->ProcessBaselines)) {
        Entry = RemoveHeadList(&Internal->ProcessBaselines);
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);
        InitializeListHead(&Baseline->ListEntry);

        //
        // Remove from hash table while holding baseline lock
        //
        if (!IsListEmpty(&Baseline->HashEntry)) {
            ULONG BucketIndex = PmpHashProcessId(Baseline->ProcessId);
            PPM_HASH_BUCKET Bucket = &Internal->HashTable[BucketIndex];

            ExAcquirePushLockExclusive(&Bucket->Lock);
            RemoveEntryList(&Baseline->HashEntry);
            InitializeListHead(&Baseline->HashEntry);
            ExReleasePushLockExclusive(&Bucket->Lock);
        }

        InsertTailList(&BaselinesToFree, &Baseline->ListEntry);
    }

    ExReleasePushLockExclusive(&Internal->BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Free baselines outside lock
    //
    while (!IsListEmpty(&BaselinesToFree)) {
        Entry = RemoveHeadList(&BaselinesToFree);
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);
        PmpFreeBaseline(Internal, Baseline);
    }

    //
    // Collect all events under lock, then free outside lock
    //
    InitializeListHead(&EventsToFree);

    KeAcquireSpinLock(&Internal->EventLock, &OldIrql);

    while (!IsListEmpty(&Internal->EventList)) {
        Entry = RemoveHeadList(&Internal->EventList);
        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        InitializeListHead(&Event->ListEntry);
        InsertTailList(&EventsToFree, &Event->ListEntry);
    }
    Internal->EventCount = 0;

    KeReleaseSpinLock(&Internal->EventLock, OldIrql);

    //
    // Free events outside lock
    //
    while (!IsListEmpty(&EventsToFree)) {
        Entry = RemoveHeadList(&EventsToFree);
        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        PmpFreeEventInternal(Internal, Event);
    }

    //
    // Delete lookaside lists
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->BaselineLookaside);
        ExDeleteNPagedLookasideList(&Internal->EventLookaside);
        Internal->LookasideInitialized = FALSE;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PrivilegeMonitor] Shutdown complete. "
        "Stats: Escalations=%lld, Legitimate=%lld, Blocked=%lld\n",
        Internal->Stats.EscalationsDetected,
        Internal->Stats.LegitimateEscalations,
        Internal->Stats.BlockedEscalations
        );

    //
    // Mark signature as dead and free
    //
    Internal->Signature = PM_MONITOR_SIGNATURE_DEAD;
    ShadowStrikeFreePoolWithTag(Internal, PM_POOL_TAG);
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmGetConfiguration(
    _In_ PPM_MONITOR Monitor,
    _Out_ PPM_CONFIG Config
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal) || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Internal->ConfigLock);

    RtlCopyMemory(Config, &Internal->Config, sizeof(PM_CONFIG));

    ExReleasePushLockShared(&Internal->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PmSetConfiguration(
    _In_ PPM_MONITOR Monitor,
    _In_ PPM_CONFIG Config
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal) || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->ConfigLock);

    RtlCopyMemory(&Internal->Config, Config, sizeof(PM_CONFIG));

    ExReleasePushLockExclusive(&Internal->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
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
    PEPROCESS ParentProcess = NULL;
    ULONG IntegrityLevel = 0;
    ULONG Privileges = 0;
    BOOLEAN IsElevated = FALSE;
    BOOLEAN IsSystem = FALSE;
    BOOLEAN IsService = FALSE;
    ULONG SessionId = 0;
    LUID AuthenticationId = {0};
    UNICODE_STRING ImageName = {0};
    HANDLE ParentProcessId = NULL;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check baseline limit
    //
    if ((ULONG)InterlockedCompareExchange(&Internal->BaselineCount, 0, 0) >= PM_MAX_BASELINES) {
        return STATUS_QUOTA_EXCEEDED;
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

    //
    // Get process name safely
    //
    Status = ShadowStrikeGetProcessImageName(ProcessId, &ImageName);
    if (NT_SUCCESS(Status) && ImageName.Buffer != NULL) {
        SIZE_T CopyLen = ImageName.Length / sizeof(WCHAR);
        if (CopyLen >= PM_MAX_PROCESS_NAME_LEN) {
            CopyLen = PM_MAX_PROCESS_NAME_LEN - 1;
        }
        RtlCopyMemory(Baseline->ProcessName, ImageName.Buffer, CopyLen * sizeof(WCHAR));
        Baseline->ProcessName[CopyLen] = L'\0';
        ShadowFreeProcessString(&ImageName);
    }

    //
    // Get parent process info
    //
    ParentProcessId = PsGetProcessInheritedFromUniqueProcessId(Process);
    Baseline->ParentProcessId = ParentProcessId;

    if (ParentProcessId != NULL) {
        Status = PsLookupProcessByProcessId(ParentProcessId, &ParentProcess);
        if (NT_SUCCESS(Status)) {
            UNICODE_STRING ParentImageName = {0};
            Status = ShadowStrikeGetProcessImageName(ParentProcessId, &ParentImageName);
            if (NT_SUCCESS(Status) && ParentImageName.Buffer != NULL) {
                SIZE_T CopyLen = ParentImageName.Length / sizeof(WCHAR);
                if (CopyLen >= PM_MAX_PROCESS_NAME_LEN) {
                    CopyLen = PM_MAX_PROCESS_NAME_LEN - 1;
                }
                RtlCopyMemory(Baseline->ParentProcessName, ParentImageName.Buffer, CopyLen * sizeof(WCHAR));
                Baseline->ParentProcessName[CopyLen] = L'\0';
                ShadowFreeProcessString(&ParentImageName);
            }
            ObDereferenceObject(ParentProcess);
        }
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
    Baseline->CurrentSessionId = SessionId;
    Baseline->CurrentAuthenticationId = AuthenticationId;

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

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->Stats.BaselinesCaptured);

    //
    // Release process reference (baseline doesn't hold it)
    //
    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PmRemoveBaseline(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal)) {
        return STATUS_INVALID_PARAMETER;
    }

    Baseline = PmpLookupBaseline(Internal, ProcessId);
    if (Baseline == NULL) {
        return STATUS_NOT_FOUND;
    }

    PmpRemoveBaselineInternal(Internal, Baseline);
    PmpDereferenceBaseline(Internal, Baseline);  // Release lookup reference
    InterlockedIncrement64(&Internal->Stats.BaselinesRemoved);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PmMarkProcessTerminated(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal)) {
        return STATUS_INVALID_PARAMETER;
    }

    Baseline = PmpLookupBaseline(Internal, ProcessId);
    if (Baseline == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Mark as terminated for deferred cleanup
    //
    Baseline->IsTerminated = TRUE;
    KeQuerySystemTime(&Baseline->LastCheckTime);

    PmpDereferenceBaseline(Internal, Baseline);

    return STATUS_SUCCESS;
}

// ============================================================================
// ESCALATION DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmCheckForEscalation(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Outptr_opt_ PPM_ESCALATION_EVENT* Event
    )
/*++
Routine Description:
    Checks if a process has escalated privileges since baseline.

Arguments:
    Monitor - Monitor instance.
    ProcessId - Process ID to check.
    Event - Receives escalation event if detected (caller must dereference).

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
    ULONG CurrentSessionId = 0;
    LUID CurrentAuthenticationId = {0};
    BOOLEAN EscalationDetected = FALSE;
    PM_ESCALATION_TYPE EscalationType = PmEscalation_None;
    CHAR TechniqueBuffer[PM_MAX_TECHNIQUE_LEN] = {0};
    ULONG PatternScore = 0;
    PM_CONFIG ConfigSnapshot;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Event != NULL) {
        *Event = NULL;
    }

    //
    // Get configuration snapshot
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Internal->ConfigLock);
    RtlCopyMemory(&ConfigSnapshot, &Internal->Config, sizeof(PM_CONFIG));
    ExReleasePushLockShared(&Internal->ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Look up baseline
    //
    Baseline = PmpLookupBaseline(Internal, ProcessId);
    if (Baseline == NULL) {
        //
        // No baseline - record one now and return
        //
        Status = PmRecordBaseline(Monitor, ProcessId);
        if (NT_SUCCESS(Status)) {
            return STATUS_NO_MORE_ENTRIES;
        }
        return Status;
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
        &CurrentSessionId,
        &CurrentAuthenticationId
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
    if (ConfigSnapshot.EnableIntegrityMonitoring &&
        CurrentIntegrity > Baseline->OriginalIntegrityLevel) {
        EscalationDetected = TRUE;
    }

    //
    // 2. Privilege addition
    //
    if (ConfigSnapshot.EnablePrivilegeMonitoring) {
        ULONG NewPrivileges = CurrentPrivileges & ~Baseline->OriginalPrivileges;
        if (NewPrivileges != 0) {
            //
            // Check for sensitive privilege additions
            //
            if (NewPrivileges & (PM_PRIV_DEBUG | PM_PRIV_TCB | PM_PRIV_LOAD_DRIVER |
                                 PM_PRIV_CREATE_TOKEN | PM_PRIV_ASSIGN_PRIMARY |
                                 PM_PRIV_SECURITY | PM_PRIV_TAKE_OWNERSHIP)) {
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
    // 4. Authentication ID change (token replacement/stealing)
    //
    if (ConfigSnapshot.EnableTokenManipulationDetection) {
        if (Baseline->AuthenticationId.LowPart != CurrentAuthenticationId.LowPart ||
            Baseline->AuthenticationId.HighPart != CurrentAuthenticationId.HighPart) {
            EscalationDetected = TRUE;
        }
    }

    //
    // 5. Cross-session escalation
    //
    if (ConfigSnapshot.EnableCrossSessionDetection) {
        if (Baseline->OriginalSessionId != CurrentSessionId &&
            CurrentSessionId == 0 &&
            Baseline->OriginalSessionId != 0) {
            //
            // Moved from user session to session 0
            //
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
        Baseline->CurrentSessionId = CurrentSessionId;
        Baseline->CurrentAuthenticationId = CurrentAuthenticationId;

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
    // Populate event with self-contained data (no external references)
    //
    NewEvent->ProcessId = ProcessId;
    NewEvent->ParentProcessId = Baseline->ParentProcessId;

    //
    // Copy process names directly into event (safe from baseline lifetime)
    //
    RtlCopyMemory(NewEvent->ProcessName, Baseline->ProcessName, sizeof(NewEvent->ProcessName));
    RtlCopyMemory(NewEvent->ParentProcessName, Baseline->ParentProcessName, sizeof(NewEvent->ParentProcessName));

    //
    // Before/after state
    //
    NewEvent->OldIntegrityLevel = Baseline->OriginalIntegrityLevel;
    NewEvent->NewIntegrityLevel = CurrentIntegrity;
    NewEvent->OldPrivileges = Baseline->OriginalPrivileges;
    NewEvent->NewPrivileges = CurrentPrivileges;
    NewEvent->OldSessionId = Baseline->OriginalSessionId;
    NewEvent->NewSessionId = CurrentSessionId;
    NewEvent->OldAuthenticationId = Baseline->AuthenticationId;
    NewEvent->NewAuthenticationId = CurrentAuthenticationId;

    //
    // Timestamps
    //
    KeQuerySystemTime(&NewEvent->Timestamp);
    NewEvent->BaselineTime = Baseline->BaselineTime;

    //
    // Determine escalation type
    //
    EscalationType = PmpDetermineEscalationType(
        Baseline,
        Baseline->OriginalIntegrityLevel,
        CurrentIntegrity,
        Baseline->OriginalPrivileges,
        CurrentPrivileges,
        Baseline->OriginalSessionId,
        CurrentSessionId,
        &Baseline->AuthenticationId,
        &CurrentAuthenticationId
        );

    //
    // Check for UAC bypass
    //
    if (ConfigSnapshot.EnableUACBypassDetection) {
        if (PmpDetectUACBypass(
                Internal,
                Baseline,
                TechniqueBuffer,
                sizeof(TechniqueBuffer),
                &PatternScore)) {
            EscalationType = PmEscalation_UACBypass;
            RtlCopyMemory(NewEvent->Technique, TechniqueBuffer, sizeof(NewEvent->Technique));
        }
    }

    NewEvent->Type = EscalationType;

    //
    // Calculate suspicion score
    //
    NewEvent->SuspicionScore = PmpCalculateSuspicionScore(NewEvent, Baseline);
    if (PatternScore > 0 && PatternScore > NewEvent->SuspicionScore) {
        NewEvent->SuspicionScore = PatternScore;
    }

    //
    // Determine if legitimate
    //
    if (PmpIsLegitimateEscalation(NewEvent, Baseline)) {
        NewEvent->Flags |= PM_EVENT_FLAG_LEGITIMATE;
        InterlockedIncrement64(&Internal->Stats.LegitimateEscalations);
    }

    //
    // Check if alertable
    //
    if (NewEvent->SuspicionScore >= ConfigSnapshot.MinAlertScore) {
        NewEvent->Flags |= PM_EVENT_FLAG_ALERTABLE;
    }

    //
    // Check if should be blocked
    //
    if (ConfigSnapshot.BlockHighRiskEscalation &&
        NewEvent->SuspicionScore >= ConfigSnapshot.BlockThresholdScore &&
        !(NewEvent->Flags & PM_EVENT_FLAG_LEGITIMATE)) {
        NewEvent->Flags |= PM_EVENT_FLAG_BLOCKED;
        InterlockedIncrement64(&Internal->Stats.BlockedEscalations);
    }

    //
    // Update baseline state
    //
    Baseline->CurrentIntegrityLevel = CurrentIntegrity;
    Baseline->CurrentPrivileges = CurrentPrivileges;
    Baseline->CurrentIsElevated = CurrentIsElevated;
    Baseline->CurrentSessionId = CurrentSessionId;
    Baseline->CurrentAuthenticationId = CurrentAuthenticationId;
    Baseline->EscalationCount++;
    Baseline->HasEscalated = TRUE;
    Baseline->Flags |= PM_BASELINE_FLAG_SUSPICIOUS;

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->Stats.EscalationsDetected);

    //
    // Insert event into list
    //
    PmpInsertEvent(Internal, NewEvent);

    //
    // Return event to caller with reference (caller must dereference)
    //
    if (Event != NULL) {
        PmReferenceEvent(NewEvent);
        *Event = NewEvent;
    }

    PmpDereferenceBaseline(Internal, Baseline);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_WARNING_LEVEL,
        "[ShadowStrike/PrivilegeMonitor] ESCALATION DETECTED: PID=%lu, Type=%d, "
        "Integrity=%lu->%lu, Privs=0x%08X->0x%08X, Score=%lu, Flags=0x%X\n",
        HandleToULong(ProcessId),
        NewEvent->Type,
        NewEvent->OldIntegrityLevel,
        NewEvent->NewIntegrityLevel,
        NewEvent->OldPrivileges,
        NewEvent->NewPrivileges,
        NewEvent->SuspicionScore,
        NewEvent->Flags
        );

    return STATUS_SUCCESS;
}

// ============================================================================
// EVENT MANAGEMENT
// ============================================================================

_Use_decl_annotations_
VOID
PmReferenceEvent(
    _In_ PPM_ESCALATION_EVENT Event
    )
{
    if (Event != NULL) {
        InterlockedIncrement(&Event->RefCount);
    }
}


_Use_decl_annotations_
VOID
PmDereferenceEvent(
    _In_ PPM_ESCALATION_EVENT Event
    )
{
    if (Event != NULL) {
        LONG NewCount = InterlockedDecrement(&Event->RefCount);
        if (NewCount == 0) {
            //
            // Event is no longer referenced, free it
            // Note: We can't use the monitor's lookaside list here since
            // the event may outlive the monitor. Use pool directly.
            //
            ShadowStrikeFreePoolWithTag(Event, PM_EVENT_POOL_TAG);
        }
    }
}


_Use_decl_annotations_
NTSTATUS
PmGetEvents(
    _In_ PPM_MONITOR Monitor,
    _Out_writes_to_(MaxEvents, *EventCount) PPM_ESCALATION_EVENT* Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventCount
    )
/*++
Routine Description:
    Gets escalation events with references.
    Caller MUST call PmDereferenceEvent on each returned event.

Arguments:
    Monitor - Monitor instance.
    Events - Array to receive event pointers.
    MaxEvents - Maximum events to return.
    EventCount - Receives number of events returned.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PLIST_ENTRY Entry;
    PPM_ESCALATION_EVENT Event;
    KIRQL OldIrql;
    ULONG Found = 0;

    if (!PmpIsValidMonitorInternal(Internal) ||
        Events == NULL || EventCount == NULL || MaxEvents == 0) {
        if (EventCount != NULL) *EventCount = 0;
        return STATUS_INVALID_PARAMETER;
    }

    *EventCount = 0;
    RtlZeroMemory(Events, MaxEvents * sizeof(PPM_ESCALATION_EVENT));

    KeAcquireSpinLock(&Internal->EventLock, &OldIrql);

    for (Entry = Internal->EventList.Flink;
         Entry != &Internal->EventList && Found < MaxEvents;
         Entry = Entry->Flink) {

        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);

        //
        // Add reference for caller
        //
        InterlockedIncrement(&Event->RefCount);
        Events[Found] = Event;
        Found++;
    }

    KeReleaseSpinLock(&Internal->EventLock, OldIrql);

    *EventCount = Found;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PmClearEvents(
    _In_ PPM_MONITOR Monitor
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    LIST_ENTRY EventsToFree;
    PLIST_ENTRY Entry;
    PPM_ESCALATION_EVENT Event;
    KIRQL OldIrql;

    if (!PmpIsValidMonitorInternal(Internal)) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&EventsToFree);

    KeAcquireSpinLock(&Internal->EventLock, &OldIrql);

    //
    // Move all events to local list
    //
    while (!IsListEmpty(&Internal->EventList)) {
        Entry = RemoveHeadList(&Internal->EventList);
        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        InitializeListHead(&Event->ListEntry);
        InsertTailList(&EventsToFree, &Event->ListEntry);
    }
    Internal->EventCount = 0;

    KeReleaseSpinLock(&Internal->EventLock, OldIrql);

    //
    // Dereference events outside lock
    //
    while (!IsListEmpty(&EventsToFree)) {
        Entry = RemoveHeadList(&EventsToFree);
        Event = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        PmDereferenceEvent(Event);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// QUERY APIs
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmQueryProcessEscalation(
    _In_ PPM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN HasEscalated,
    _Out_ PULONG EscalationCount,
    _Out_ PULONG CurrentIntegrityLevel
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;
    PPM_PROCESS_BASELINE Baseline;

    PAGED_CODE();

    if (!PmpIsValidMonitorInternal(Internal)) {
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


_Use_decl_annotations_
NTSTATUS
PmGetStatistics(
    _In_ PPM_MONITOR Monitor,
    _Out_ PPM_STATISTICS Statistics
    )
{
    PPM_MONITOR_INTERNAL Internal = (PPM_MONITOR_INTERNAL)Monitor;

    if (!PmpIsValidMonitorInternal(Internal) || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic reads of statistics
    //
    Statistics->EscalationsDetected = InterlockedCompareExchange64(
        &Internal->Stats.EscalationsDetected, 0, 0);
    Statistics->LegitimateEscalations = InterlockedCompareExchange64(
        &Internal->Stats.LegitimateEscalations, 0, 0);
    Statistics->BlockedEscalations = InterlockedCompareExchange64(
        &Internal->Stats.BlockedEscalations, 0, 0);
    Statistics->BaselinesCaptured = InterlockedCompareExchange64(
        &Internal->Stats.BaselinesCaptured, 0, 0);
    Statistics->BaselinesRemoved = InterlockedCompareExchange64(
        &Internal->Stats.BaselinesRemoved, 0, 0);
    Statistics->CurrentBaselineCount = InterlockedCompareExchange(
        &Internal->BaselineCount, 0, 0);
    Statistics->CurrentEventCount = InterlockedCompareExchange(
        &Internal->EventCount, 0, 0);
    Statistics->StartTime = Internal->Stats.StartTime;
    Statistics->LastCleanupTime = Internal->Stats.LastCleanupTime;

    return STATUS_SUCCESS;
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

    ExFreeToNPagedLookasideList(&Monitor->BaselineLookaside, Baseline);
}


static ULONG
PmpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    //
    // FNV-1a inspired hash
    //
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
    PPM_PROCESS_BASELINE Found = NULL;

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
            Found = Baseline;
            break;
        }
    }

    ExReleasePushLockShared(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return Found;
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
    // LOCK ORDERING: Baseline lock first, then hash bucket lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->BaselineLock);

    InsertTailList(&Monitor->ProcessBaselines, &Baseline->ListEntry);
    InterlockedIncrement(&Monitor->BaselineCount);

    //
    // Insert into hash table
    //
    BucketIndex = PmpHashProcessId(Baseline->ProcessId);
    Bucket = &Monitor->HashTable[BucketIndex];

    ExAcquirePushLockExclusive(&Bucket->Lock);
    InsertTailList(&Bucket->List, &Baseline->HashEntry);
    ExReleasePushLockExclusive(&Bucket->Lock);

    ExReleasePushLockExclusive(&Monitor->BaselineLock);
    KeLeaveCriticalRegion();
}


static VOID
PmpRemoveBaselineInternal(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline
    )
{
    ULONG BucketIndex;
    PPM_HASH_BUCKET Bucket;
    BOOLEAN WasInList = FALSE;

    //
    // LOCK ORDERING: Baseline lock first, then hash bucket lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->BaselineLock);

    //
    // Remove from main list
    //
    if (!IsListEmpty(&Baseline->ListEntry)) {
        RemoveEntryList(&Baseline->ListEntry);
        InitializeListHead(&Baseline->ListEntry);
        InterlockedDecrement(&Monitor->BaselineCount);
        WasInList = TRUE;
    }

    //
    // Remove from hash table
    //
    BucketIndex = PmpHashProcessId(Baseline->ProcessId);
    Bucket = &Monitor->HashTable[BucketIndex];

    ExAcquirePushLockExclusive(&Bucket->Lock);
    if (!IsListEmpty(&Baseline->HashEntry)) {
        RemoveEntryList(&Baseline->HashEntry);
        InitializeListHead(&Baseline->HashEntry);
    }
    ExReleasePushLockExclusive(&Bucket->Lock);

    ExReleasePushLockExclusive(&Monitor->BaselineLock);
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
// EVENT MANAGEMENT HELPERS
// ============================================================================

static PPM_ESCALATION_EVENT
PmpAllocateEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor
    )
{
    PPM_ESCALATION_EVENT Event;

    //
    // Allocate from pool directly (not lookaside) so events can outlive monitor
    //
    Event = (PPM_ESCALATION_EVENT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PM_ESCALATION_EVENT),
        PM_EVENT_POOL_TAG
        );

    if (Event != NULL) {
        RtlZeroMemory(Event, sizeof(PM_ESCALATION_EVENT));
        Event->RefCount = 1;  // Initial reference for list
        InitializeListHead(&Event->ListEntry);
    }

    UNREFERENCED_PARAMETER(Monitor);
    return Event;
}


static VOID
PmpFreeEventInternal(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_ESCALATION_EVENT Event
    )
{
    UNREFERENCED_PARAMETER(Monitor);

    if (Event != NULL) {
        ShadowStrikeFreePoolWithTag(Event, PM_EVENT_POOL_TAG);
    }
}


static VOID
PmpInsertEvent(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_ESCALATION_EVENT Event
    )
{
    KIRQL OldIrql;
    LIST_ENTRY EventsToFree;
    PLIST_ENTRY Entry;
    PPM_ESCALATION_EVENT OldEvent;

    InitializeListHead(&EventsToFree);

    KeAcquireSpinLock(&Monitor->EventLock, &OldIrql);

    //
    // Enforce limit by removing oldest events
    // Keep lock held during entire operation to prevent races
    //
    while ((ULONG)Monitor->EventCount >= PM_MAX_EVENTS &&
           !IsListEmpty(&Monitor->EventList)) {

        Entry = RemoveHeadList(&Monitor->EventList);
        OldEvent = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        InitializeListHead(&OldEvent->ListEntry);
        InsertTailList(&EventsToFree, &OldEvent->ListEntry);
        InterlockedDecrement(&Monitor->EventCount);
    }

    //
    // Insert new event
    //
    InsertTailList(&Monitor->EventList, &Event->ListEntry);
    InterlockedIncrement(&Monitor->EventCount);
    InterlockedIncrement(&Monitor->Stats.CurrentEventCount);

    KeReleaseSpinLock(&Monitor->EventLock, OldIrql);

    //
    // Dereference old events outside lock
    //
    while (!IsListEmpty(&EventsToFree)) {
        Entry = RemoveHeadList(&EventsToFree);
        OldEvent = CONTAINING_RECORD(Entry, PM_ESCALATION_EVENT, ListEntry);
        PmDereferenceEvent(OldEvent);
    }
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

    //
    // Initialize outputs
    //
    *IntegrityLevel = PM_INTEGRITY_MEDIUM;
    *Privileges = PM_PRIV_NONE;
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
            Status = STATUS_SUCCESS;  // Non-fatal
        }

        //
        // Get authentication ID
        //
        Status = SeQueryAuthenticationIdToken(Token, AuthenticationId);
        if (!NT_SUCCESS(Status)) {
            RtlZeroMemory(AuthenticationId, sizeof(LUID));
            Status = STATUS_SUCCESS;  // Non-fatal
        }

        //
        // Check for admin token
        //
        if (SeTokenIsAdmin(Token)) {
            *IsElevated = TRUE;
        }

        //
        // Get actual integrity level from token
        //
        *IntegrityLevel = PmpGetTokenIntegrityLevel(Token);

        //
        // Get privilege flags (actually enumerate privileges)
        //
        *Privileges = PmpConvertPrivilegesToFlags(Token);

        //
        // Check for SYSTEM token
        //
        if (*SessionId == 0 && *IntegrityLevel >= PM_INTEGRITY_SYSTEM) {
            *IsSystem = TRUE;
        }

        //
        // Check for service (session 0, elevated, not SYSTEM)
        //
        if (*SessionId == 0 && *IsElevated && !*IsSystem) {
            *IsService = TRUE;
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
PmpGetTokenIntegrityLevel(
    _In_ PACCESS_TOKEN Token
    )
/*++
Routine Description:
    Gets the actual integrity level from a token.

Arguments:
    Token - Token to query.

Return Value:
    Integrity level value.
--*/
{
    NTSTATUS Status;
    ULONG IntegrityLevel = PM_INTEGRITY_MEDIUM;
    PSID IntegritySid = NULL;

    //
    // Get the token integrity level SID
    //
    Status = SeQueryInformationToken(
        Token,
        TokenIntegrityLevel,
        &IntegritySid
        );

    if (NT_SUCCESS(Status) && IntegritySid != NULL) {
        //
        // The integrity level is in the last subauthority
        //
        PISID Sid = (PISID)IntegritySid;
        if (Sid->SubAuthorityCount > 0) {
            ULONG IntegrityRid = Sid->SubAuthority[Sid->SubAuthorityCount - 1];

            //
            // Map RID to our integrity level values
            //
            if (IntegrityRid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
                IntegrityLevel = PM_INTEGRITY_PROTECTED;
            } else if (IntegrityRid >= SECURITY_MANDATORY_SYSTEM_RID) {
                IntegrityLevel = PM_INTEGRITY_SYSTEM;
            } else if (IntegrityRid >= SECURITY_MANDATORY_HIGH_RID) {
                IntegrityLevel = PM_INTEGRITY_HIGH;
            } else if (IntegrityRid >= SECURITY_MANDATORY_MEDIUM_PLUS_RID) {
                IntegrityLevel = PM_INTEGRITY_MEDIUM_PLUS;
            } else if (IntegrityRid >= SECURITY_MANDATORY_MEDIUM_RID) {
                IntegrityLevel = PM_INTEGRITY_MEDIUM;
            } else if (IntegrityRid >= SECURITY_MANDATORY_LOW_RID) {
                IntegrityLevel = PM_INTEGRITY_LOW;
            } else {
                IntegrityLevel = PM_INTEGRITY_UNTRUSTED;
            }
        }

        ExFreePool(IntegritySid);
    }

    return IntegrityLevel;
}


static ULONG
PmpConvertPrivilegesToFlags(
    _In_ PACCESS_TOKEN Token
    )
/*++
Routine Description:
    Converts token privileges to our internal bit flags.
    Actually enumerates the token privileges.

Arguments:
    Token - Token to query.

Return Value:
    Privilege bit flags.
--*/
{
    ULONG Flags = PM_PRIV_NONE;
    LUID PrivilegeLuid;
    BOOLEAN HasPrivilege;

    //
    // Check each sensitive privilege
    //

    // SE_DEBUG_PRIVILEGE
    PrivilegeLuid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
    if (SePrivilegeCheck(&(PRIVILEGE_SET){1, PRIVILEGE_SET_ALL_NECESSARY,
        {{PrivilegeLuid, SE_PRIVILEGE_ENABLED}}},
        &((SECURITY_SUBJECT_CONTEXT){0, Token, Token, 0}),
        UserMode)) {
        Flags |= PM_PRIV_DEBUG;
    }

    //
    // Alternative method: Use SeCheckTokenPrivilege for common privileges
    //

    // SE_TCB_PRIVILEGE
    PrivilegeLuid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
    HasPrivilege = FALSE;
    if (SeSinglePrivilegeCheck(PrivilegeLuid, KernelMode)) {
        // Note: This checks current token, not the passed token
        // For accurate checking, we'd need to use SePrivilegeCheck
    }

    //
    // Check commonly abused privileges by examining token directly
    // This is a simplified check - full implementation would iterate TOKEN_PRIVILEGES
    //
    __try {
        PTOKEN_PRIVILEGES TokenPrivileges = NULL;
        ULONG ReturnLength = 0;
        NTSTATUS Status;

        Status = SeQueryInformationToken(
            Token,
            TokenPrivileges,
            &TokenPrivileges
            );

        if (NT_SUCCESS(Status) && TokenPrivileges != NULL) {
            for (ULONG i = 0; i < TokenPrivileges->PrivilegeCount; i++) {
                PLUID_AND_ATTRIBUTES Priv = &TokenPrivileges->Privileges[i];

                //
                // Only count enabled or default-enabled privileges
                //
                if (!(Priv->Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))) {
                    continue;
                }

                LONG PrivValue = Priv->Luid.LowPart;

                switch (PrivValue) {
                    case SE_DEBUG_PRIVILEGE:
                        Flags |= PM_PRIV_DEBUG;
                        break;
                    case SE_TCB_PRIVILEGE:
                        Flags |= PM_PRIV_TCB;
                        break;
                    case SE_LOAD_DRIVER_PRIVILEGE:
                        Flags |= PM_PRIV_LOAD_DRIVER;
                        break;
                    case SE_IMPERSONATE_PRIVILEGE:
                        Flags |= PM_PRIV_IMPERSONATE;
                        break;
                    case SE_ASSIGNPRIMARYTOKEN_PRIVILEGE:
                        Flags |= PM_PRIV_ASSIGN_PRIMARY;
                        break;
                    case SE_CREATE_TOKEN_PRIVILEGE:
                        Flags |= PM_PRIV_CREATE_TOKEN;
                        break;
                    case SE_BACKUP_PRIVILEGE:
                        Flags |= PM_PRIV_BACKUP;
                        break;
                    case SE_RESTORE_PRIVILEGE:
                        Flags |= PM_PRIV_RESTORE;
                        break;
                    case SE_TAKE_OWNERSHIP_PRIVILEGE:
                        Flags |= PM_PRIV_TAKE_OWNERSHIP;
                        break;
                    case SE_SECURITY_PRIVILEGE:
                        Flags |= PM_PRIV_SECURITY;
                        break;
                    case SE_SYSTEM_ENVIRONMENT_PRIVILEGE:
                        Flags |= PM_PRIV_SYSTEM_ENVIRONMENT;
                        break;
                    case SE_INCREASE_QUOTA_PRIVILEGE:
                        Flags |= PM_PRIV_INCREASE_QUOTA;
                        break;
                    case SE_INCREASE_BASE_PRIORITY_PRIVILEGE:
                        Flags |= PM_PRIV_INCREASE_PRIORITY;
                        break;
                    case SE_CREATE_PAGEFILE_PRIVILEGE:
                        Flags |= PM_PRIV_CREATE_PAGEFILE;
                        break;
                    case SE_SHUTDOWN_PRIVILEGE:
                        Flags |= PM_PRIV_SHUTDOWN;
                        break;
                    case SE_AUDIT_PRIVILEGE:
                        Flags |= PM_PRIV_AUDIT;
                        break;
                    case SE_SYSTEM_PROFILE_PRIVILEGE:
                        Flags |= PM_PRIV_SYSTEM_PROFILE;
                        break;
                    case SE_SYSTEMTIME_PRIVILEGE:
                        Flags |= PM_PRIV_SYSTEMTIME;
                        break;
                    case SE_MANAGE_VOLUME_PRIVILEGE:
                        Flags |= PM_PRIV_MANAGE_VOLUME;
                        break;
                }
            }

            ExFreePool(TokenPrivileges);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Ignore exceptions during privilege enumeration
    }

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
    _In_ ULONG NewPrivileges,
    _In_ ULONG OldSessionId,
    _In_ ULONG NewSessionId,
    _In_ PLUID OldAuthId,
    _In_ PLUID NewAuthId
    )
{
    ULONG AddedPrivileges = NewPrivileges & ~OldPrivileges;

    UNREFERENCED_PARAMETER(Baseline);

    //
    // Check for token manipulation first (most severe)
    //
    if (OldAuthId->LowPart != NewAuthId->LowPart ||
        OldAuthId->HighPart != NewAuthId->HighPart) {
        return PmEscalation_TokenManipulation;
    }

    //
    // Check for cross-session escalation
    //
    if (OldSessionId != NewSessionId && NewSessionId == 0 && OldSessionId != 0) {
        return PmEscalation_CrossSession;
    }

    //
    // Check for integrity increase
    //
    if (NewIntegrity > OldIntegrity) {
        if (OldIntegrity <= PM_INTEGRITY_MEDIUM && NewIntegrity >= PM_INTEGRITY_HIGH) {
            return PmEscalation_TokenElevation;
        }
        if (NewIntegrity >= PM_INTEGRITY_SYSTEM) {
            return PmEscalation_ExploitKernel;
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
        if (AddedPrivileges & (PM_PRIV_TCB | PM_PRIV_CREATE_TOKEN)) {
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
            Score += 95;
            break;

        case PmEscalation_TokenManipulation:
            Score += 90;
            break;

        case PmEscalation_UACBypass:
            Score += 85;
            break;

        case PmEscalation_CrossSession:
            Score += 80;
            break;

        case PmEscalation_TokenElevation:
            Score += 65;
            break;

        case PmEscalation_DriverLoad:
            Score += 75;
            break;

        case PmEscalation_ServiceCreation:
            Score += 55;
            break;

        case PmEscalation_IntegrityIncrease:
            Score += 45;
            break;

        case PmEscalation_PrivilegeEnable:
            Score += 35;
            break;

        default:
            Score += 20;
    }

    //
    // Adjust for integrity jump magnitude
    //
    if (Event->NewIntegrityLevel > Event->OldIntegrityLevel) {
        ULONG Jump = Event->NewIntegrityLevel - Event->OldIntegrityLevel;
        if (Jump >= 0x3000) {        // Multiple levels (e.g., Low to High)
            Score += 25;
        } else if (Jump >= 0x2000) { // Two levels
            Score += 15;
        } else if (Jump >= 0x1000) { // One level
            Score += 5;
        }
    }

    //
    // Sensitive privilege additions
    //
    ULONG NewPrivs = Event->NewPrivileges & ~Event->OldPrivileges;
    if (NewPrivs & PM_PRIV_DEBUG) Score += 15;
    if (NewPrivs & PM_PRIV_TCB) Score += 30;
    if (NewPrivs & PM_PRIV_LOAD_DRIVER) Score += 25;
    if (NewPrivs & PM_PRIV_CREATE_TOKEN) Score += 30;
    if (NewPrivs & PM_PRIV_ASSIGN_PRIMARY) Score += 20;
    if (NewPrivs & PM_PRIV_SECURITY) Score += 15;
    if (NewPrivs & PM_PRIV_TAKE_OWNERSHIP) Score += 10;
    if (NewPrivs & PM_PRIV_BACKUP) Score += 10;
    if (NewPrivs & PM_PRIV_RESTORE) Score += 10;

    //
    // Non-elevated process gaining elevation
    //
    if (!Baseline->OriginalIsElevated && Event->NewIntegrityLevel >= PM_INTEGRITY_HIGH) {
        Score += 15;
    }

    //
    // Non-system process gaining system integrity
    //
    if (!Baseline->OriginalIsSystem && Event->NewIntegrityLevel >= PM_INTEGRITY_SYSTEM) {
        Score += 25;
    }

    //
    // Session 0 escalation from user session
    //
    if (Baseline->OriginalSessionId != 0 && Event->NewSessionId == 0) {
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
    ULONG i;

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
    // Check against known legitimate elevation processes
    //
    if (Event->ProcessName[0] != L'\0') {
        for (i = 0; i < PM_LEGITIMATE_PROCESS_COUNT; i++) {
            if (PmpCompareUnicodeStringInsensitive(
                    Event->ProcessName,
                    g_LegitimateElevationProcesses[i])) {
                return TRUE;
            }
        }
    }

    //
    // Low suspicion score suggests legitimate
    //
    if (Event->SuspicionScore < PM_SUSPICION_LOW) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
PmpDetectUACBypass(
    _In_ PPM_MONITOR_INTERNAL Monitor,
    _In_ PPM_PROCESS_BASELINE Baseline,
    _Out_writes_bytes_(TechniqueBufferSize) PCHAR TechniqueBuffer,
    _In_ ULONG TechniqueBufferSize,
    _Out_ PULONG PatternScore
    )
{
    ULONG i;

    UNREFERENCED_PARAMETER(Monitor);

    TechniqueBuffer[0] = '\0';
    *PatternScore = 0;

    if (Baseline->ProcessName[0] == L'\0') {
        return FALSE;
    }

    for (i = 0; i < PM_UAC_BYPASS_PATTERN_COUNT; i++) {
        const PM_UAC_BYPASS_PATTERN* Pattern = &g_UACBypassPatterns[i];
        BOOLEAN ProcessMatch = FALSE;
        BOOLEAN ParentMatch = TRUE;  // Default to true if no parent specified

        //
        // Check process name match
        //
        if (PmpCompareUnicodeStringInsensitive(Baseline->ProcessName, Pattern->ProcessName)) {
            ProcessMatch = TRUE;
        }

        if (!ProcessMatch) {
            continue;
        }

        //
        // Check parent process if specified
        //
        if (Pattern->ParentProcessName != NULL) {
            ParentMatch = FALSE;
            if (Baseline->ParentProcessName[0] != L'\0') {
                if (PmpCompareUnicodeStringInsensitive(
                        Baseline->ParentProcessName,
                        Pattern->ParentProcessName)) {
                    ParentMatch = TRUE;
                }
            }
        }

        if (!ParentMatch) {
            //
            // Process matches but parent doesn't - still suspicious but lower score
            //
            if (*PatternScore < Pattern->SuspicionScore / 2) {
                *PatternScore = Pattern->SuspicionScore / 2;
            }
            continue;
        }

        //
        // Full match found
        //
        RtlStringCchCopyA(
            TechniqueBuffer,
            TechniqueBufferSize,
            Pattern->TechniqueName
            );
        *PatternScore = Pattern->SuspicionScore;

        return TRUE;
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
/*++
Routine Description:
    DPC callback for cleanup timer.
    Runs at DISPATCH_LEVEL so cannot perform cleanup directly.
    Queues a work item to run at PASSIVE_LEVEL.

Arguments:
    Standard DPC arguments.
--*/
{
    PPM_MONITOR_INTERNAL Monitor = (PPM_MONITOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Monitor == NULL || Monitor->ShutdownRequested) {
        return;
    }

    if (Monitor->CleanupWorkItem == NULL) {
        return;
    }

    //
    // Try to set cleanup in progress flag
    //
    if (InterlockedCompareExchange(&Monitor->CleanupInProgress, 1, 0) != 0) {
        //
        // Cleanup already in progress
        //
        return;
    }

    //
    // Queue work item to run at PASSIVE_LEVEL
    //
    IoQueueWorkItem(
        Monitor->CleanupWorkItem,
        PmpCleanupWorkRoutine,
        DelayedWorkQueue,
        Monitor
        );
}


VOID
PmpCleanupWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Work routine for cleanup. Runs at PASSIVE_LEVEL.

Arguments:
    DeviceObject - Device object (unused).
    Context - Monitor pointer.
--*/
{
    PPM_MONITOR_INTERNAL Monitor = (PPM_MONITOR_INTERNAL)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Monitor == NULL || Monitor->ShutdownRequested) {
        if (Monitor != NULL) {
            InterlockedExchange(&Monitor->CleanupInProgress, 0);
        }
        return;
    }

    //
    // Perform cleanup at PASSIVE_LEVEL
    //
    PmpCleanupStaleBaselines(Monitor);

    //
    // Update last cleanup time
    //
    KeQuerySystemTime(&Monitor->Stats.LastCleanupTime);

    //
    // Clear in-progress flag
    //
    InterlockedExchange(&Monitor->CleanupInProgress, 0);
}


static VOID
PmpCleanupStaleBaselines(
    _In_ PPM_MONITOR_INTERNAL Monitor
    )
/*++
Routine Description:
    Cleans up baselines for terminated processes.
    MUST be called at PASSIVE_LEVEL or APC_LEVEL.
--*/
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PPM_PROCESS_BASELINE Baseline;
    LIST_ENTRY StaleList;
    ULONG BucketIndex;
    PPM_HASH_BUCKET Bucket;
    PEPROCESS Process;
    NTSTATUS Status;

    PAGED_CODE();

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)PM_BASELINE_TIMEOUT_MS * 10000;

    //
    // First pass: identify stale baselines under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->BaselineLock);

    for (Entry = Monitor->ProcessBaselines.Flink;
         Entry != &Monitor->ProcessBaselines;
         Entry = Next) {

        Next = Entry->Flink;
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);

        BOOLEAN ShouldRemove = FALSE;

        if (Baseline->IsTerminated) {
            //
            // Check timeout
            //
            if ((CurrentTime.QuadPart - Baseline->LastCheckTime.QuadPart) > TimeoutInterval.QuadPart) {
                ShouldRemove = TRUE;
            }
        } else {
            //
            // Check if process still exists
            //
            Status = PsLookupProcessByProcessId(Baseline->ProcessId, &Process);
            if (!NT_SUCCESS(Status)) {
                //
                // Process no longer exists, mark for cleanup
                //
                Baseline->IsTerminated = TRUE;
                KeQuerySystemTime(&Baseline->LastCheckTime);
            } else {
                //
                // Check if terminating
                //
                if (PsGetProcessExitStatus(Process) != STATUS_PENDING) {
                    Baseline->IsTerminated = TRUE;
                    KeQuerySystemTime(&Baseline->LastCheckTime);
                }
                ObDereferenceObject(Process);
            }
        }

        if (ShouldRemove) {
            //
            // Remove from main list
            //
            RemoveEntryList(&Baseline->ListEntry);
            InitializeListHead(&Baseline->ListEntry);
            InterlockedDecrement(&Monitor->BaselineCount);

            //
            // Remove from hash table while holding baseline lock
            //
            BucketIndex = PmpHashProcessId(Baseline->ProcessId);
            Bucket = &Monitor->HashTable[BucketIndex];

            ExAcquirePushLockExclusive(&Bucket->Lock);
            if (!IsListEmpty(&Baseline->HashEntry)) {
                RemoveEntryList(&Baseline->HashEntry);
                InitializeListHead(&Baseline->HashEntry);
            }
            ExReleasePushLockExclusive(&Bucket->Lock);

            //
            // Add to stale list for freeing outside lock
            //
            InsertTailList(&StaleList, &Baseline->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Monitor->BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Free stale baselines outside lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Baseline = CONTAINING_RECORD(Entry, PM_PROCESS_BASELINE, ListEntry);

        //
        // Release list reference (may free baseline)
        //
        PmpDereferenceBaseline(Monitor, Baseline);

        InterlockedIncrement64(&Monitor->Stats.BaselinesRemoved);
    }
}
