/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ATTACK CHAIN TRACKER
 * ============================================================================
 *
 * @file AttackChainTracker.c
 * @brief Enterprise-grade multi-stage attack correlation and kill chain tracking.
 *
 * Implements Enterprise-grade attack chain detection with:
 * - Real-time MITRE ATT&CK technique correlation
 * - Kill chain phase progression tracking
 * - Process relationship correlation (parent/child, injection targets)
 * - Temporal correlation (events within time windows)
 * - Confidence scoring based on technique combinations
 * - Automatic attack chain creation and merging
 * - Alert callback for confirmed attacks
 * - Evidence collection and preservation
 * - Reference-counted chain objects for thread-safe lifetime
 * - Periodic cleanup of expired chains
 *
 * Lock Ordering (must be acquired in this order to prevent deadlock):
 * 1. Tracker->ChainLock (push lock)
 * 2. Chain->EventLock (spinlock)
 * 3. Tracker->CallbackLock (spinlock)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma warning(push)
#pragma warning(disable:4324)
#include "AttackChainTracker.h"
#pragma warning(pop)
#include <ntstrsafe.h>

static VOID ActpCleanupWorkerThread(_In_ PVOID StartContext);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ActInitialize)
#pragma alloc_text(PAGE, ActShutdown)
#pragma alloc_text(PAGE, ActRegisterCallback)
#pragma alloc_text(PAGE, ActUnregisterCallback)
#pragma alloc_text(PAGE, ActGetChain)
#pragma alloc_text(PAGE, ActCorrelateEvents)
#pragma alloc_text(PAGE, ActGetActiveChains)
#pragma alloc_text(PAGE, ActpCleanupWorkerThread)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Chain expiration time (30 minutes in 100ns units)
 */
#define ACT_CHAIN_EXPIRY_TIME           (30LL * 60 * 10000000LL)

/**
 * @brief Cleanup timer interval (5 minutes in 100ns units, negative = relative)
 */
#define ACT_CLEANUP_INTERVAL            (-5LL * 60 * 10000000LL)

/**
 * @brief Minimum score to confirm attack
 */
#define ACT_CONFIRM_THRESHOLD           300

/**
 * @brief Minimum phases for confirmed attack
 */
#define ACT_MIN_PHASES_FOR_CONFIRM      3

// ============================================================================
// TECHNIQUE TO PHASE MAPPING
// ============================================================================

typedef struct _ACT_TECHNIQUE_PHASE_MAP {
    ULONG TechniqueBase;        // Base technique ID (without sub-technique)
    ACT_CHAIN_STATE Phase;      // Kill chain phase
    ULONG BaseScore;            // Base threat score for this technique
} ACT_TECHNIQUE_PHASE_MAP;

/**
 * @brief Mapping of MITRE techniques to kill chain phases
 */
static const ACT_TECHNIQUE_PHASE_MAP g_TechniquePhaseMap[] = {
    //
    // Initial Access techniques
    //
    { MITRE_T1566 & 0xFFFF, ActState_InitialAccess, 40 },       // Phishing
    { MITRE_T1189 & 0xFFFF, ActState_InitialAccess, 50 },       // Drive-by Compromise
    { MITRE_T1190 & 0xFFFF, ActState_InitialAccess, 60 },       // Exploit Public-Facing App
    { MITRE_T1091 & 0xFFFF, ActState_InitialAccess, 35 },       // Removable Media

    //
    // Execution techniques
    //
    { MITRE_T1059 & 0xFFFF, ActState_Execution, 30 },           // Command/Scripting
    { MITRE_T1106 & 0xFFFF, ActState_Execution, 25 },           // Native API
    { MITRE_T1053 & 0xFFFF, ActState_Execution, 35 },           // Scheduled Task
    { MITRE_T1047 & 0xFFFF, ActState_Execution, 40 },           // WMI
    { MITRE_T1204 & 0xFFFF, ActState_Execution, 30 },           // User Execution
    { MITRE_T1569 & 0xFFFF, ActState_Execution, 35 },           // System Services

    //
    // Persistence techniques
    //
    { MITRE_T1547 & 0xFFFF, ActState_Persistence, 50 },         // Boot/Logon Autostart
    { MITRE_T1543 & 0xFFFF, ActState_Persistence, 55 },         // Create System Process
    { MITRE_T1546 & 0xFFFF, ActState_Persistence, 45 },         // Event Triggered Execution
    { MITRE_T1574 & 0xFFFF, ActState_Persistence, 50 },         // Hijack Execution Flow
    { MITRE_T1197 & 0xFFFF, ActState_Persistence, 40 },         // BITS Jobs
    { MITRE_T1505 & 0xFFFF, ActState_Persistence, 60 },         // Web Shell

    //
    // Privilege Escalation techniques
    //
    { MITRE_T1548 & 0xFFFF, ActState_PrivilegeEscalation, 60 }, // Abuse Elevation Control
    { MITRE_T1134 & 0xFFFF, ActState_PrivilegeEscalation, 55 }, // Access Token Manipulation
    { MITRE_T1068 & 0xFFFF, ActState_PrivilegeEscalation, 70 }, // Exploitation for PrivEsc
    { MITRE_T1055 & 0xFFFF, ActState_PrivilegeEscalation, 65 }, // Process Injection

    //
    // Defense Evasion techniques
    //
    { MITRE_T1140 & 0xFFFF, ActState_DefenseEvasion, 35 },      // Deobfuscate/Decode
    { MITRE_T1562 & 0xFFFF, ActState_DefenseEvasion, 70 },      // Impair Defenses
    { MITRE_T1070 & 0xFFFF, ActState_DefenseEvasion, 55 },      // Indicator Removal
    { MITRE_T1036 & 0xFFFF, ActState_DefenseEvasion, 45 },      // Masquerading
    { MITRE_T1027 & 0xFFFF, ActState_DefenseEvasion, 40 },      // Obfuscated Files
    { MITRE_T1218 & 0xFFFF, ActState_DefenseEvasion, 50 },      // System Binary Proxy
    { MITRE_T1112 & 0xFFFF, ActState_DefenseEvasion, 35 },      // Modify Registry
    { MITRE_T1497 & 0xFFFF, ActState_DefenseEvasion, 30 },      // VM/Sandbox Evasion
    { MITRE_T1014 & 0xFFFF, ActState_DefenseEvasion, 80 },      // Rootkit
    { MITRE_T1620 & 0xFFFF, ActState_DefenseEvasion, 55 },      // Reflective Code Loading

    //
    // Credential Access techniques
    //
    { MITRE_T1003 & 0xFFFF, ActState_CredentialAccess, 75 },    // OS Credential Dumping
    { MITRE_T1555 & 0xFFFF, ActState_CredentialAccess, 60 },    // Credentials from Stores
    { MITRE_T1056 & 0xFFFF, ActState_CredentialAccess, 55 },    // Input Capture (Keylogging)
    { MITRE_T1558 & 0xFFFF, ActState_CredentialAccess, 70 },    // Kerberos Tickets
    { MITRE_T1110 & 0xFFFF, ActState_CredentialAccess, 45 },    // Brute Force
    { MITRE_T1557 & 0xFFFF, ActState_CredentialAccess, 50 },    // MITM

    //
    // Discovery techniques
    //
    { MITRE_T1087 & 0xFFFF, ActState_Discovery, 20 },           // Account Discovery
    { MITRE_T1083 & 0xFFFF, ActState_Discovery, 15 },           // File/Dir Discovery
    { MITRE_T1057 & 0xFFFF, ActState_Discovery, 15 },           // Process Discovery
    { MITRE_T1082 & 0xFFFF, ActState_Discovery, 15 },           // System Info Discovery
    { MITRE_T1016 & 0xFFFF, ActState_Discovery, 20 },           // Network Config Discovery
    { MITRE_T1018 & 0xFFFF, ActState_Discovery, 25 },           // Remote System Discovery
    { MITRE_T1135 & 0xFFFF, ActState_Discovery, 25 },           // Network Share Discovery

    //
    // Lateral Movement techniques
    //
    { MITRE_T1021 & 0xFFFF, ActState_LateralMovement, 55 },     // Remote Services
    { MITRE_T1210 & 0xFFFF, ActState_LateralMovement, 65 },     // Exploitation of Remote Services
    { MITRE_T1570 & 0xFFFF, ActState_LateralMovement, 50 },     // Lateral Tool Transfer
    { MITRE_T1080 & 0xFFFF, ActState_LateralMovement, 45 },     // Taint Shared Content

    //
    // Collection techniques
    //
    { MITRE_T1560 & 0xFFFF, ActState_Collection, 40 },          // Archive Collected Data
    { MITRE_T1005 & 0xFFFF, ActState_Collection, 30 },          // Data from Local System
    { MITRE_T1039 & 0xFFFF, ActState_Collection, 35 },          // Data from Network Share
    { MITRE_T1113 & 0xFFFF, ActState_Collection, 35 },          // Screen Capture
    { MITRE_T1115 & 0xFFFF, ActState_Collection, 25 },          // Clipboard Data
    { MITRE_T1114 & 0xFFFF, ActState_Collection, 40 },          // Email Collection

    //
    // Exfiltration techniques
    //
    { MITRE_T1041 & 0xFFFF, ActState_Exfiltration, 60 },        // Exfil Over C2
    { MITRE_T1048 & 0xFFFF, ActState_Exfiltration, 55 },        // Exfil Over Alt Protocol
    { MITRE_T1567 & 0xFFFF, ActState_Exfiltration, 50 },        // Exfil Over Web Service
    { MITRE_T1020 & 0xFFFF, ActState_Exfiltration, 45 },        // Automated Exfiltration

    //
    // Impact techniques
    //
    { MITRE_T1486 & 0xFFFF, ActState_Impact, 100 },             // Ransomware
    { MITRE_T1485 & 0xFFFF, ActState_Impact, 90 },              // Data Destruction
    { MITRE_T1490 & 0xFFFF, ActState_Impact, 85 },              // Inhibit System Recovery
    { MITRE_T1489 & 0xFFFF, ActState_Impact, 70 },              // Service Stop
    { MITRE_T1496 & 0xFFFF, ActState_Impact, 55 },              // Resource Hijacking (Mining)

    //
    // End marker
    //
    { 0, ActState_Initial, 0 }
};

// ============================================================================
// DANGEROUS TECHNIQUE COMBINATIONS
// ============================================================================

typedef struct _ACT_DANGEROUS_COMBO {
    ULONG Technique1;
    ULONG Technique2;
    ULONG BonusScore;           // Extra score when both techniques seen
    ULONG ComboIndex;           // Index for bitmask tracking (0-31)
    PCSTR Description;
} ACT_DANGEROUS_COMBO;

static const ACT_DANGEROUS_COMBO g_DangerousCombos[] = {
    //
    // Credential dumping + Lateral movement = Active breach
    //
    { MITRE_T1003 & 0xFFFF, MITRE_T1021 & 0xFFFF, 100, 0, "Credential theft with lateral movement" },

    //
    // Defense evasion + Process injection = Stealthy code execution
    //
    { MITRE_T1562 & 0xFFFF, MITRE_T1055 & 0xFFFF, 80, 1, "Defense evasion with process injection" },

    //
    // Persistence + Privilege escalation = Entrenched attacker
    //
    { MITRE_T1547 & 0xFFFF, MITRE_T1548 & 0xFFFF, 70, 2, "Persistence with privilege escalation" },

    //
    // Collection + Exfiltration = Data theft in progress
    //
    { MITRE_T1560 & 0xFFFF, MITRE_T1041 & 0xFFFF, 90, 3, "Data archiving with exfiltration" },

    //
    // Ransomware indicators
    //
    { MITRE_T1486 & 0xFFFF, MITRE_T1490 & 0xFFFF, 150, 4, "Ransomware with recovery inhibition" },

    //
    // End marker
    //
    { 0, 0, 0, 0, NULL }
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static ACT_CHAIN_STATE
ActpGetPhaseForTechnique(
    _In_ ULONG TechniqueId,
    _Out_ PULONG BaseScore
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PACT_ATTACK_CHAIN
ActpFindChainForProcessLocked(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static PACT_ATTACK_CHAIN
ActpCreateChain(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static PACT_CHAIN_EVENT
ActpCreateEvent(
    _In_ ULONG TechniqueId,
    _In_ ACT_CHAIN_STATE Phase,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ ULONG Score,
    _In_reads_bytes_opt_(EvidenceSize) PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpFreeEvent(
    _In_ PACT_CHAIN_EVENT Event
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpFreeChainInternal(
    _In_ PACT_ATTACK_CHAIN Chain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpAddEventToChainLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ PACT_CHAIN_EVENT Event,
    _Out_opt_ PACT_CHAIN_EVENT* EvictedEvent
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpUpdateChainScoreLocked(
    _In_ PACT_ATTACK_CHAIN Chain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
ActpIsChainExpiredLocked(
    _In_ PACT_ATTACK_CHAIN Chain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpAddRelatedProcessLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
ActpIsProcessRelatedLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
ActpCountPhasesLocked(
    _In_ PACT_ATTACK_CHAIN Chain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpCheckDangerousCombosLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ ULONG NewTechnique
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpGenerateChainId(
    _Out_ PGUID ChainId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
ActpSaturatingAdd(
    _In_ ULONG Value,
    _In_ ULONG Addend
    );

// ============================================================================
// INLINE UTILITIES
// ============================================================================

/**
 * @brief Saturating addition for ULONG - prevents overflow
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
ActpSaturatingAdd(
    _In_ ULONG Value,
    _In_ ULONG Addend
    )
{
    if (Value > MAXULONG - Addend) {
        return MAXULONG;
    }
    return Value + Addend;
}

// ============================================================================
// PUBLIC API - REFERENCE COUNTING
// ============================================================================

/**
 * @brief Add a reference to a chain.
 *
 * @param Chain   Chain to reference.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ActReferenceChain(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    if (Chain != NULL) {
        LONG newCount = InterlockedIncrement(&Chain->ReferenceCount);
        NT_ASSERT(newCount > 1);
        UNREFERENCED_PARAMETER(newCount);
    }
}

/**
 * @brief Release a reference to a chain. Frees when count reaches zero.
 *
 * @param Chain   Chain to release.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ActReleaseChain(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    if (Chain != NULL) {
        LONG newCount = InterlockedDecrement(&Chain->ReferenceCount);
        NT_ASSERT(newCount >= 0);

        if (newCount == 0) {
            ActpFreeChainInternal(Chain);
        }
    }
}

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the attack chain tracker.
 *
 * @param Tracker   Receives initialized tracker handle.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ActInitialize(
    _Out_ PACT_TRACKER* Tracker
    )
{
    PACT_TRACKER tracker = NULL;

    PAGED_CODE();

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    //
    // Allocate tracker structure from NonPagedPoolNx
    //
    tracker = (PACT_TRACKER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ACT_TRACKER),
        ACT_POOL_TAG
    );

    if (tracker == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize chain list and lock
    //
    InitializeListHead(&tracker->ChainList);
    ExInitializePushLock(&tracker->ChainLock);
    tracker->ChainCount = 0;

    //
    // Initialize callback registration
    //
    tracker->CallbackReg = NULL;
    KeInitializeSpinLock(&tracker->CallbackLock);

    //
    // Initialize cleanup thread synchronization
    //
    KeInitializeEvent(&tracker->CleanupWakeEvent, SynchronizationEvent, FALSE);
    tracker->CleanupStopping = FALSE;
    tracker->CleanupThread = NULL;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&tracker->Stats.StartTime);

    //
    // Mark as initialized (must be last before starting thread)
    //
    InterlockedExchange(&tracker->Initialized, TRUE);

    //
    // Start cleanup worker thread
    //
    {
        HANDLE threadHandle = NULL;
        NTSTATUS threadStatus;
        OBJECT_ATTRIBUTES oa;

        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        threadStatus = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            &oa,
            NULL,
            NULL,
            ActpCleanupWorkerThread,
            tracker
        );

        if (NT_SUCCESS(threadStatus)) {
            NTSTATUS refStatus = ObReferenceObjectByHandle(
                threadHandle,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode,
                (PVOID*)&tracker->CleanupThread,
                NULL
            );

            if (!NT_SUCCESS(refStatus)) {
                //
                // Thread is running but ObRef failed.
                // Signal termination and wait via handle before closing.
                //
                InterlockedExchange(&tracker->CleanupStopping, TRUE);
                KeSetEvent(&tracker->CleanupWakeEvent, IO_NO_INCREMENT, FALSE);

                ZwWaitForSingleObject(threadHandle, FALSE, NULL);
                tracker->CleanupThread = NULL;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] AttackChainTracker: ObReferenceObjectByHandle failed (0x%08X)\n",
                           refStatus);
            }

            ZwClose(threadHandle);
        } else {
            //
            // Non-fatal: tracker works without periodic cleanup
            // Chains will accumulate but memory is bounded by ACT_MAX_ACTIVE_CHAINS
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] AttackChainTracker: cleanup thread creation failed (0x%08X)\n",
                       threadStatus);
        }
    }

    *Tracker = tracker;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Attack chain tracker initialized\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the attack chain tracker.
 *
 * @param Tracker   Tracker to shutdown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ActShutdown(
    _Inout_ PACT_TRACKER Tracker
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    LIST_ENTRY tempList;
    PACT_CALLBACK_REGISTRATION oldReg;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Tracker == NULL) {
        return;
    }

    if (InterlockedExchange(&Tracker->Initialized, FALSE) == FALSE) {
        return;
    }

    //
    // Signal cleanup thread to stop and wait for it
    //
    InterlockedExchange(&Tracker->CleanupStopping, TRUE);
    KeSetEvent(&Tracker->CleanupWakeEvent, IO_NO_INCREMENT, FALSE);

    if (Tracker->CleanupThread != NULL) {
        KeWaitForSingleObject(
            Tracker->CleanupThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        ObDereferenceObject(Tracker->CleanupThread);
        Tracker->CleanupThread = NULL;
    }

    //
    // Clear callback registration
    //
    KeAcquireSpinLock(&Tracker->CallbackLock, &oldIrql);
    oldReg = Tracker->CallbackReg;
    Tracker->CallbackReg = NULL;
    KeReleaseSpinLock(&Tracker->CallbackLock, oldIrql);

    if (oldReg != NULL) {
        ExFreePoolWithTag(oldReg, ACT_CALLBACK_TAG);
    }

    InitializeListHead(&tempList);

    //
    // Move all chains to temp list under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ChainLock);

    while (!IsListEmpty(&Tracker->ChainList)) {
        listEntry = RemoveHeadList(&Tracker->ChainList);
        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);
        InitializeListHead(&chain->ListEntry);
        InsertTailList(&tempList, listEntry);
    }

    Tracker->ChainCount = 0;

    ExReleasePushLockExclusive(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    //
    // Release references on all chains (will free when refcount hits zero)
    //
    while (!IsListEmpty(&tempList)) {
        listEntry = RemoveHeadList(&tempList);
        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);
        InitializeListHead(&chain->ListEntry);
        ActReleaseChain(chain);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Attack chain tracker shutdown (events=%lld, chains=%lld, expired=%lld, attacks=%lld)\n",
               Tracker->Stats.EventsProcessed,
               Tracker->Stats.ChainsCreated,
               Tracker->Stats.ChainsExpired,
               Tracker->Stats.AttacksConfirmed);

    ExFreePoolWithTag(Tracker, ACT_POOL_TAG);
}

// ============================================================================
// PUBLIC API - CALLBACK REGISTRATION
// ============================================================================

/**
 * @brief Register callback for attack alerts.
 *
 * Thread-safe atomic registration. Previous callback (if any) is replaced.
 *
 * @param Tracker   Tracker handle.
 * @param Callback  Callback function.
 * @param Context   User context passed to callback.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActRegisterCallback(
    _In_ PACT_TRACKER Tracker,
    _In_ ACT_CHAIN_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PACT_CALLBACK_REGISTRATION newReg;
    PACT_CALLBACK_REGISTRATION oldReg;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Tracker == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate new registration structure
    //
    newReg = (PACT_CALLBACK_REGISTRATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ACT_CALLBACK_REGISTRATION),
        ACT_CALLBACK_TAG
    );

    if (newReg == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    newReg->Callback = (PVOID)Callback;
    newReg->Context = Context;

    //
    // Atomically swap in new registration
    //
    KeAcquireSpinLock(&Tracker->CallbackLock, &oldIrql);
    oldReg = Tracker->CallbackReg;
    Tracker->CallbackReg = newReg;
    KeReleaseSpinLock(&Tracker->CallbackLock, oldIrql);

    //
    // Free old registration if any
    //
    if (oldReg != NULL) {
        ExFreePoolWithTag(oldReg, ACT_CALLBACK_TAG);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister the current callback.
 *
 * @param Tracker   Tracker handle.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ActUnregisterCallback(
    _In_ PACT_TRACKER Tracker
    )
{
    PACT_CALLBACK_REGISTRATION oldReg;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Tracker == NULL) {
        return;
    }

    KeAcquireSpinLock(&Tracker->CallbackLock, &oldIrql);
    oldReg = Tracker->CallbackReg;
    Tracker->CallbackReg = NULL;
    KeReleaseSpinLock(&Tracker->CallbackLock, oldIrql);

    if (oldReg != NULL) {
        ExFreePoolWithTag(oldReg, ACT_CALLBACK_TAG);
    }
}

// ============================================================================
// PUBLIC API - EVENT SUBMISSION
// ============================================================================

/**
 * @brief Submit a detected technique event for correlation.
 *
 * @param Tracker       Tracker handle.
 * @param Technique     MITRE technique ID.
 * @param ProcessId     Process that triggered the event.
 * @param ProcessName   Process name (optional, kernel buffer only).
 * @param Evidence      Optional evidence data (kernel buffer only).
 * @param EvidenceSize  Size of evidence.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActSubmitEvent(
    _In_ PACT_TRACKER Tracker,
    _In_ ULONG Technique,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_reads_bytes_opt_(EvidenceSize) PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    )
{
    PACT_ATTACK_CHAIN chain = NULL;
    PACT_CHAIN_EVENT event = NULL;
    PACT_CHAIN_EVENT evictedEvent = NULL;
    ACT_CHAIN_STATE phase;
    ULONG baseScore = 0;
    BOOLEAN newChain = FALSE;
    BOOLEAN confirmedAttack = FALSE;
    KIRQL eventIrql;
    ACT_CHAIN_CALLBACK callback = NULL;
    PVOID callbackContext = NULL;
    PACT_CALLBACK_REGISTRATION callbackReg;
    KIRQL callbackIrql;
    ACT_CHAIN_EVENT eventSnapshot;

    if (Tracker == NULL || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate ProcessName if provided
    //
    if (ProcessName != NULL) {
        if (ProcessName->Buffer == NULL && ProcessName->Length > 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (ProcessName->Length > ACT_MAX_PROCESS_NAME_LEN) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    //
    // Validate Evidence
    //
    if (Evidence != NULL && EvidenceSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Evidence == NULL && EvidenceSize > 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (EvidenceSize > ACT_MAX_EVIDENCE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&Tracker->Stats.EventsProcessed);

    //
    // Determine phase and score for this technique
    //
    phase = ActpGetPhaseForTechnique(Technique, &baseScore);

    if (phase == ActState_Initial) {
        //
        // Unknown technique - use default discovery phase
        //
        phase = ActState_Discovery;
        baseScore = 10;
    }

    //
    // Find or create chain for this process
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ChainLock);

    chain = ActpFindChainForProcessLocked(Tracker, ProcessId);

    if (chain == NULL) {
        //
        // Create new chain if under limit
        //
        if ((ULONG)Tracker->ChainCount < ACT_MAX_ACTIVE_CHAINS) {
            chain = ActpCreateChain(ProcessId, ProcessName);
            if (chain != NULL) {
                //
                // Chain starts with refcount = 1 (for tracker list)
                //
                InsertHeadList(&Tracker->ChainList, &chain->ListEntry);
                InterlockedIncrement(&Tracker->ChainCount);
                InterlockedIncrement64(&Tracker->Stats.ChainsCreated);
                newChain = TRUE;
            }
        }
    }

    if (chain == NULL) {
        ExReleasePushLockExclusive(&Tracker->ChainLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Take reference for our use (separate from tracker list reference)
    //
    ActReferenceChain(chain);

    ExReleasePushLockExclusive(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    //
    // Create event
    //
    event = ActpCreateEvent(
        Technique,
        phase,
        ProcessId,
        ProcessName,
        baseScore,
        Evidence,
        EvidenceSize
    );

    if (event == NULL) {
        if (newChain) {
            //
            // Remove the chain we just added
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Tracker->ChainLock);
            RemoveEntryList(&chain->ListEntry);
            InitializeListHead(&chain->ListEntry);
            InterlockedDecrement(&Tracker->ChainCount);
            ExReleasePushLockExclusive(&Tracker->ChainLock);
            KeLeaveCriticalRegion();

            //
            // Release tracker's reference (will free since refcount becomes 1->0 after our release)
            //
            ActReleaseChain(chain);
        }
        ActReleaseChain(chain);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Add event to chain under EventLock
    //
    KeAcquireSpinLock(&chain->EventLock, &eventIrql);

    ActpAddEventToChainLocked(chain, event, &evictedEvent);
    ActpAddRelatedProcessLocked(chain, ProcessId);

    //
    // Update chain state
    //
    if (phase > chain->CurrentState) {
        chain->CurrentState = phase;
    }

    //
    // Update last activity time
    //
    KeQuerySystemTime(&chain->LastActivityTime);

    //
    // Check for dangerous technique combinations
    //
    ActpCheckDangerousCombosLocked(chain, Technique);

    //
    // Update chain score
    //
    ActpUpdateChainScoreLocked(chain);

    //
    // Check if attack is now confirmed
    //
    if (!chain->IsConfirmedAttack) {
        ULONG phaseCount = ActpCountPhasesLocked(chain);

        if (chain->ThreatScore >= ACT_CONFIRM_THRESHOLD &&
            phaseCount >= ACT_MIN_PHASES_FOR_CONFIRM) {

            chain->IsConfirmedAttack = TRUE;
            confirmedAttack = TRUE;
            InterlockedIncrement64(&Tracker->Stats.AttacksConfirmed);

            //
            // Snapshot event data while under EventLock to prevent
            // use-after-free if concurrent eviction frees the event
            // between lock release and callback invocation.
            //
            RtlCopyMemory(&eventSnapshot, event, sizeof(ACT_CHAIN_EVENT));
            eventSnapshot.ProcessName.Buffer = NULL;
            eventSnapshot.ProcessName.Length = 0;
            eventSnapshot.ProcessName.MaximumLength = 0;
            eventSnapshot.EvidenceData = NULL;
            eventSnapshot.EvidenceSize = 0;
            InitializeListHead(&eventSnapshot.ListEntry);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] ATTACK CONFIRMED: Chain %08lX-%04hX Score=%u Phases=%u\n",
                       chain->ChainId.Data1,
                       chain->ChainId.Data2,
                       chain->ThreatScore,
                       phaseCount);
        }
    }

    KeReleaseSpinLock(&chain->EventLock, eventIrql);

    //
    // Free evicted event outside lock
    //
    if (evictedEvent != NULL) {
        ActpFreeEvent(evictedEvent);
    }

    //
    // Get callback atomically
    //
    if (confirmedAttack) {
        KeAcquireSpinLock(&Tracker->CallbackLock, &callbackIrql);
        callbackReg = Tracker->CallbackReg;
        if (callbackReg != NULL) {
            callback = (ACT_CHAIN_CALLBACK)callbackReg->Callback;
            callbackContext = callbackReg->Context;
        }
        KeReleaseSpinLock(&Tracker->CallbackLock, callbackIrql);

        //
        // Fire callback with chain reference held and stack-safe event snapshot.
        // The snapshot contains technique, phase, process ID, score, and timestamp.
        // Heap-allocated fields (ProcessName.Buffer, EvidenceData) are NULLed
        // as they belong to the original event which may be concurrently evicted.
        //
        if (callback != NULL) {
            callback(chain, &eventSnapshot, callbackContext);
        }
    }

    //
    // Release our reference
    //
    ActReleaseChain(chain);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CHAIN QUERIES
// ============================================================================

/**
 * @brief Get attack chain by ID.
 *
 * Returns chain with reference added. Caller must call ActReleaseChain.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActGetChain(
    _In_ PACT_TRACKER Tracker,
    _In_ PGUID ChainId,
    _Outptr_ PACT_ATTACK_CHAIN* Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    PACT_ATTACK_CHAIN found = NULL;

    PAGED_CODE();

    if (Tracker == NULL || ChainId == NULL || Chain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Chain = NULL;

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->ChainLock);

    for (listEntry = Tracker->ChainList.Flink;
         listEntry != &Tracker->ChainList;
         listEntry = listEntry->Flink) {

        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);

        if (RtlCompareMemory(&chain->ChainId, ChainId, sizeof(GUID)) == sizeof(GUID)) {
            //
            // Take reference before returning
            //
            ActReferenceChain(chain);
            found = chain;
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Chain = found;
    return STATUS_SUCCESS;
}

/**
 * @brief Find attack chain correlated with a process.
 *
 * Returns chain with reference added. Caller must call ActReleaseChain.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActCorrelateEvents(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Outptr_ PACT_ATTACK_CHAIN* Chain
    )
{
    PACT_ATTACK_CHAIN found = NULL;

    PAGED_CODE();

    if (Tracker == NULL || ProcessId == NULL || Chain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Chain = NULL;

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->ChainLock);

    found = ActpFindChainForProcessLocked(Tracker, ProcessId);
    if (found != NULL) {
        ActReferenceChain(found);
    }

    ExReleasePushLockShared(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Chain = found;
    return STATUS_SUCCESS;
}

/**
 * @brief Get all active (non-expired) attack chains.
 *
 * Returns chains with references added. Caller must call ActReleaseChain on each.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActGetActiveChains(
    _In_ PACT_TRACKER Tracker,
    _Out_writes_to_(MaxChains, *ChainCount) PACT_ATTACK_CHAIN* Chains,
    _In_ ULONG MaxChains,
    _Out_ PULONG ChainCount
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    ULONG count = 0;
    KIRQL oldIrql;
    BOOLEAN expired;

    PAGED_CODE();

    if (Tracker == NULL || Chains == NULL || ChainCount == NULL || MaxChains == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ChainCount = 0;

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->ChainLock);

    for (listEntry = Tracker->ChainList.Flink;
         listEntry != &Tracker->ChainList && count < MaxChains;
         listEntry = listEntry->Flink) {

        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);

        //
        // Check expiration under EventLock
        //
        KeAcquireSpinLock(&chain->EventLock, &oldIrql);
        expired = ActpIsChainExpiredLocked(chain);
        KeReleaseSpinLock(&chain->EventLock, oldIrql);

        if (!expired) {
            ActReferenceChain(chain);
            Chains[count++] = chain;
        }
    }

    ExReleasePushLockShared(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    *ChainCount = count;
    return STATUS_SUCCESS;
}

// ============================================================================
// CLEANUP WORKER THREAD
// ============================================================================

/**
 * @brief Worker thread for periodic chain cleanup.
 *
 * Runs at PASSIVE_LEVEL. Wakes every 5 minutes or when signaled.
 * Safely acquires push locks for chain expiration scanning.
 *
 * @param StartContext   Tracker pointer.
 *
 * @irql PASSIVE_LEVEL
 */
static VOID
ActpCleanupWorkerThread(
    _In_ PVOID StartContext
    )
{
    PACT_TRACKER tracker = (PACT_TRACKER)StartContext;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PACT_ATTACK_CHAIN chain;
    LIST_ENTRY expiredList;
    KIRQL eventIrql;
    BOOLEAN expired;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    PAGED_CODE();

    //
    // 5-minute cleanup interval (negative = relative, in 100ns units)
    //
    timeout.QuadPart = -5LL * 60 * 10000000LL;

    while (!tracker->CleanupStopping) {

        //
        // Wait for wake event or timeout
        //
        waitStatus = KeWaitForSingleObject(
            &tracker->CleanupWakeEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (tracker->CleanupStopping) {
            break;
        }

        //
        // STATUS_TIMEOUT means we woke on schedule; STATUS_SUCCESS means signaled
        //
        UNREFERENCED_PARAMETER(waitStatus);

        InitializeListHead(&expiredList);

        //
        // Scan for expired chains under exclusive lock at PASSIVE_LEVEL
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&tracker->ChainLock);

        for (listEntry = tracker->ChainList.Flink;
             listEntry != &tracker->ChainList;
             listEntry = nextEntry) {

            nextEntry = listEntry->Flink;
            chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);

            KeAcquireSpinLock(&chain->EventLock, &eventIrql);
            expired = ActpIsChainExpiredLocked(chain);
            KeReleaseSpinLock(&chain->EventLock, eventIrql);

            if (expired) {
                RemoveEntryList(&chain->ListEntry);
                InitializeListHead(&chain->ListEntry);
                InsertTailList(&expiredList, &chain->ListEntry);
                InterlockedDecrement(&tracker->ChainCount);
                InterlockedIncrement64(&tracker->Stats.ChainsExpired);
            }
        }

        ExReleasePushLockExclusive(&tracker->ChainLock);
        KeLeaveCriticalRegion();

        //
        // Release references on expired chains outside lock
        //
        while (!IsListEmpty(&expiredList)) {
            listEntry = RemoveHeadList(&expiredList);
            chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);
            InitializeListHead(&chain->ListEntry);
            ActReleaseChain(chain);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// PRIVATE IMPLEMENTATION
// ============================================================================

/**
 * @brief Get kill chain phase for a technique.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ACT_CHAIN_STATE
ActpGetPhaseForTechnique(
    _In_ ULONG TechniqueId,
    _Out_ PULONG BaseScore
    )
{
    ULONG baseTechnique = TechniqueId & 0xFFFF;
    ULONG i;

    *BaseScore = 10;  // Default score

    for (i = 0; g_TechniquePhaseMap[i].TechniqueBase != 0; i++) {
        if (g_TechniquePhaseMap[i].TechniqueBase == baseTechnique) {
            *BaseScore = g_TechniquePhaseMap[i].BaseScore;
            return g_TechniquePhaseMap[i].Phase;
        }
    }

    return ActState_Initial;
}

/**
 * @brief Find chain for process. Caller must hold ChainLock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static PACT_ATTACK_CHAIN
ActpFindChainForProcessLocked(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    KIRQL oldIrql;
    BOOLEAN expired;
    BOOLEAN related;

    for (listEntry = Tracker->ChainList.Flink;
         listEntry != &Tracker->ChainList;
         listEntry = listEntry->Flink) {

        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);

        //
        // Check under EventLock for thread safety
        //
        KeAcquireSpinLock(&chain->EventLock, &oldIrql);

        expired = ActpIsChainExpiredLocked(chain);
        if (!expired) {
            //
            // Check if this is the root process or a related process
            //
            if (chain->RootProcessId == ProcessId) {
                KeReleaseSpinLock(&chain->EventLock, oldIrql);
                return chain;
            }

            related = ActpIsProcessRelatedLocked(chain, ProcessId);
            if (related) {
                KeReleaseSpinLock(&chain->EventLock, oldIrql);
                return chain;
            }
        }

        KeReleaseSpinLock(&chain->EventLock, oldIrql);
    }

    return NULL;
}

/**
 * @brief Create a new attack chain.
 *
 * Returns chain with ReferenceCount = 1.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static PACT_ATTACK_CHAIN
ActpCreateChain(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName
    )
{
    PACT_ATTACK_CHAIN chain;
    USHORT copyLength;

    chain = (PACT_ATTACK_CHAIN)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ACT_ATTACK_CHAIN),
        ACT_CHAIN_TAG
    );

    if (chain == NULL) {
        return NULL;
    }

    //
    // Initialize reference count to 1 (for the caller/tracker list)
    //
    chain->ReferenceCount = 1;

    //
    // Generate unique chain ID using ExUuidCreate
    //
    ActpGenerateChainId(&chain->ChainId);

    chain->CurrentState = ActState_Initial;
    chain->RootProcessId = ProcessId;

    //
    // Copy process name with validation
    //
    if (ProcessName != NULL &&
        ProcessName->Buffer != NULL &&
        ProcessName->Length > 0) {

        copyLength = min(ProcessName->Length, ACT_MAX_PROCESS_NAME_LEN);

        chain->RootProcessName.MaximumLength = copyLength + sizeof(WCHAR);
        chain->RootProcessName.Buffer = (PWCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            chain->RootProcessName.MaximumLength,
            ACT_CHAIN_TAG
        );

        if (chain->RootProcessName.Buffer != NULL) {
            RtlCopyMemory(chain->RootProcessName.Buffer,
                          ProcessName->Buffer,
                          copyLength);
            chain->RootProcessName.Length = copyLength;
        } else {
            //
            // Allocation failed - continue with empty name
            //
            chain->RootProcessName.Length = 0;
            chain->RootProcessName.MaximumLength = 0;
        }
    }

    KeQuerySystemTime(&chain->StartTime);
    chain->LastActivityTime = chain->StartTime;

    InitializeListHead(&chain->EventList);
    KeInitializeSpinLock(&chain->EventLock);
    chain->EventCount = 0;

    chain->ThreatScore = 0;
    chain->ConfidenceScore = 0;
    chain->IsConfirmedAttack = FALSE;
    chain->AppliedComboMask = 0;

    //
    // Add root process to related list
    //
    chain->RelatedProcessIds[0] = ProcessId;
    chain->RelatedProcessCount = 1;

    InitializeListHead(&chain->ListEntry);

    return chain;
}

/**
 * @brief Create a new chain event.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static PACT_CHAIN_EVENT
ActpCreateEvent(
    _In_ ULONG TechniqueId,
    _In_ ACT_CHAIN_STATE Phase,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ ULONG Score,
    _In_reads_bytes_opt_(EvidenceSize) PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    )
{
    PACT_CHAIN_EVENT event;
    USHORT copyLength;

    event = (PACT_CHAIN_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ACT_CHAIN_EVENT),
        ACT_EVENT_TAG
    );

    if (event == NULL) {
        return NULL;
    }

    event->Technique = TechniqueId;
    event->Phase = Phase;
    event->ProcessId = ProcessId;
    event->ConfidenceScore = Score;

    KeQuerySystemTime(&event->Timestamp);

    //
    // Copy process name with validation
    //
    if (ProcessName != NULL &&
        ProcessName->Buffer != NULL &&
        ProcessName->Length > 0) {

        copyLength = min(ProcessName->Length, ACT_MAX_PROCESS_NAME_LEN);

        event->ProcessName.MaximumLength = copyLength + sizeof(WCHAR);
        event->ProcessName.Buffer = (PWCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            event->ProcessName.MaximumLength,
            ACT_EVENT_TAG
        );

        if (event->ProcessName.Buffer != NULL) {
            RtlCopyMemory(event->ProcessName.Buffer,
                          ProcessName->Buffer,
                          copyLength);
            event->ProcessName.Length = copyLength;
        }
    }

    //
    // Copy evidence if provided (already validated by caller)
    //
    if (Evidence != NULL && EvidenceSize > 0) {
        event->EvidenceData = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            EvidenceSize,
            ACT_EVENT_TAG
        );

        if (event->EvidenceData != NULL) {
            RtlCopyMemory(event->EvidenceData, Evidence, EvidenceSize);
            event->EvidenceSize = EvidenceSize;
        }
    }

    //
    // Generate evidence description
    //
    RtlStringCchPrintfA(
        event->EvidenceDescription,
        sizeof(event->EvidenceDescription),
        "Technique T%04X detected in PID %p",
        TechniqueId & 0xFFFF,
        ProcessId
    );

    InitializeListHead(&event->ListEntry);

    return event;
}

/**
 * @brief Free an event and its resources.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpFreeEvent(
    _In_ PACT_CHAIN_EVENT Event
    )
{
    if (Event == NULL) {
        return;
    }

    if (Event->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Event->ProcessName.Buffer, ACT_EVENT_TAG);
    }

    if (Event->EvidenceData != NULL) {
        ExFreePoolWithTag(Event->EvidenceData, ACT_EVENT_TAG);
    }

    ExFreePoolWithTag(Event, ACT_EVENT_TAG);
}

/**
 * @brief Free a chain and all its resources.
 *
 * Called when reference count reaches zero.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpFreeChainInternal(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    LIST_ENTRY tempList;
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    KIRQL oldIrql;

    if (Chain == NULL) {
        return;
    }

    InitializeListHead(&tempList);

    //
    // Move all events to temp list under spinlock
    //
    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    while (!IsListEmpty(&Chain->EventList)) {
        listEntry = RemoveHeadList(&Chain->EventList);
        InsertTailList(&tempList, listEntry);
    }
    Chain->EventCount = 0;

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);

    //
    // Free events outside spinlock
    //
    while (!IsListEmpty(&tempList)) {
        listEntry = RemoveHeadList(&tempList);
        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        ActpFreeEvent(event);
    }

    //
    // Free process name buffer
    //
    if (Chain->RootProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Chain->RootProcessName.Buffer, ACT_CHAIN_TAG);
    }

    //
    // Free chain structure
    //
    ExFreePoolWithTag(Chain, ACT_CHAIN_TAG);
}

/**
 * @brief Add event to chain. Caller must hold EventLock.
 *
 * @param Chain         Chain to add event to.
 * @param Event         Event to add.
 * @param EvictedEvent  Receives evicted event if max reached (caller must free).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpAddEventToChainLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ PACT_CHAIN_EVENT Event,
    _Out_opt_ PACT_CHAIN_EVENT* EvictedEvent
    )
{
    PLIST_ENTRY oldEntry;

    if (EvictedEvent != NULL) {
        *EvictedEvent = NULL;
    }

    if (Chain->EventCount < ACT_MAX_CHAIN_EVENTS) {
        InsertTailList(&Chain->EventList, &Event->ListEntry);
        InterlockedIncrement(&Chain->EventCount);
    } else {
        //
        // Evict oldest event to make room
        //
        PACT_CHAIN_EVENT oldEvent;
        oldEntry = RemoveHeadList(&Chain->EventList);
        oldEvent = CONTAINING_RECORD(oldEntry, ACT_CHAIN_EVENT, ListEntry);
        InsertTailList(&Chain->EventList, &Event->ListEntry);

        if (EvictedEvent != NULL) {
            *EvictedEvent = oldEvent;
        } else {
            //
            // Caller didn't provide eviction output.
            // Cannot free under spinlock (ExFreePoolWithTag at DISPATCH is
            // safe for NonPaged, but keep consistent with the intended pattern).
            // Free directly since NonPaged pool free is IRQL-safe.
            //
            NT_ASSERT(FALSE);
            ActpFreeEvent(oldEvent);
        }
    }
}

/**
 * @brief Update chain scores. Caller must hold EventLock.
 *
 * Recalculates ThreatScore from all event scores plus applied combo bonuses.
 * Combo bonuses are tracked via AppliedComboMask and reconstructed from
 * the g_DangerousCombos table to prevent overwrite of bonus scores.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpUpdateChainScoreLocked(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    ULONG totalScore = 0;
    ULONG eventCount = 0;
    ULONG phaseCount;
    ULONG i;
    ULONG comboBonus = 0;

    for (listEntry = Chain->EventList.Flink;
         listEntry != &Chain->EventList;
         listEntry = listEntry->Flink) {

        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        totalScore = ActpSaturatingAdd(totalScore, event->ConfidenceScore);
        eventCount++;
    }

    //
    // Reconstruct combo bonus from applied combo bitmask
    //
    for (i = 0; g_DangerousCombos[i].Technique1 != 0; i++) {
        if (Chain->AppliedComboMask & (1 << g_DangerousCombos[i].ComboIndex)) {
            comboBonus = ActpSaturatingAdd(comboBonus, g_DangerousCombos[i].BonusScore);
        }
    }

    Chain->ThreatScore = ActpSaturatingAdd(totalScore, comboBonus);

    //
    // Confidence based on event count and phase progression
    //
    if (eventCount > 0) {
        phaseCount = ActpCountPhasesLocked(Chain);
        ULONG confidence = ActpSaturatingAdd(eventCount * 10, phaseCount * 15);
        Chain->ConfidenceScore = min(100, confidence);
    }
}

/**
 * @brief Check if chain is expired. Caller must hold EventLock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
ActpIsChainExpiredLocked(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    LARGE_INTEGER currentTime;

    //
    // Confirmed attacks don't expire
    //
    if (Chain->IsConfirmedAttack) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Check against last activity time
    //
    return (currentTime.QuadPart - Chain->LastActivityTime.QuadPart) > ACT_CHAIN_EXPIRY_TIME;
}

/**
 * @brief Add process to related list. Caller must hold EventLock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpAddRelatedProcessLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    //
    // Check if already in list
    //
    for (i = 0; i < Chain->RelatedProcessCount; i++) {
        if (Chain->RelatedProcessIds[i] == ProcessId) {
            return;
        }
    }

    //
    // Add if space available
    //
    if (Chain->RelatedProcessCount < ACT_MAX_RELATED_PROCESSES) {
        Chain->RelatedProcessIds[Chain->RelatedProcessCount++] = ProcessId;
    }
}

/**
 * @brief Check if process is in related list. Caller must hold EventLock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
ActpIsProcessRelatedLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    for (i = 0; i < Chain->RelatedProcessCount; i++) {
        if (Chain->RelatedProcessIds[i] == ProcessId) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Count unique phases in chain. Caller must hold EventLock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
ActpCountPhasesLocked(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    ULONG phaseMask = 0;
    ULONG count = 0;
    ULONG i;

    for (listEntry = Chain->EventList.Flink;
         listEntry != &Chain->EventList;
         listEntry = listEntry->Flink) {

        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        if (event->Phase < 32) {
            phaseMask |= (1 << event->Phase);
        }
    }

    //
    // Count bits set
    //
    for (i = 0; i < 32; i++) {
        if (phaseMask & (1 << i)) {
            count++;
        }
    }

    return count;
}

/**
 * @brief Check for dangerous technique combinations. Caller must hold EventLock.
 *
 * Uses bitmask to track which combos have already been applied to avoid
 * duplicate scoring.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpCheckDangerousCombosLocked(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ ULONG NewTechnique
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    ULONG newBase = NewTechnique & 0xFFFF;
    ULONG i;
    ULONG comboBit;

    for (listEntry = Chain->EventList.Flink;
         listEntry != &Chain->EventList;
         listEntry = listEntry->Flink) {

        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        ULONG existingBase = event->Technique & 0xFFFF;

        //
        // Check against dangerous combos
        //
        for (i = 0; g_DangerousCombos[i].Technique1 != 0; i++) {
            comboBit = 1 << g_DangerousCombos[i].ComboIndex;

            //
            // Skip if this combo was already applied
            //
            if (Chain->AppliedComboMask & comboBit) {
                continue;
            }

            if ((g_DangerousCombos[i].Technique1 == newBase &&
                 g_DangerousCombos[i].Technique2 == existingBase) ||
                (g_DangerousCombos[i].Technique2 == newBase &&
                 g_DangerousCombos[i].Technique1 == existingBase)) {

                //
                // Mark combo as applied
                //
                Chain->AppliedComboMask |= comboBit;

                //
                // Add bonus score with saturation
                //
                Chain->ThreatScore = ActpSaturatingAdd(
                    Chain->ThreatScore,
                    g_DangerousCombos[i].BonusScore
                );

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Dangerous combo detected: %s (+%u)\n",
                           g_DangerousCombos[i].Description,
                           g_DangerousCombos[i].BonusScore);
            }
        }
    }
}

/**
 * @brief Generate a unique chain ID using IRQL-safe primitives.
 *
 * Uses KeQueryPerformanceCounter + KeQuerySystemTime + atomic counter.
 * ExUuidCreate requires PASSIVE_LEVEL, which is not guaranteed here
 * since this may be called under push lock (APC_LEVEL).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ActpGenerateChainId(
    _Out_ PGUID ChainId
    )
{
    static volatile LONG s_ChainSequence = 0;
    LARGE_INTEGER timestamp;
    LARGE_INTEGER perfCounter;
    LONG sequence;

    KeQuerySystemTime(&timestamp);
    perfCounter = KeQueryPerformanceCounter(NULL);
    sequence = InterlockedIncrement(&s_ChainSequence);

    ChainId->Data1 = (ULONG)(timestamp.LowPart ^ perfCounter.LowPart);
    ChainId->Data2 = (USHORT)(sequence & 0xFFFF);
    ChainId->Data3 = (USHORT)((perfCounter.LowPart >> 16) & 0xFFFF);
    ChainId->Data4[0] = (UCHAR)(timestamp.HighPart & 0xFF);
    ChainId->Data4[1] = (UCHAR)((timestamp.HighPart >> 8) & 0xFF);
    ChainId->Data4[2] = (UCHAR)((perfCounter.HighPart) & 0xFF);
    ChainId->Data4[3] = (UCHAR)((perfCounter.HighPart >> 8) & 0xFF);
    ChainId->Data4[4] = (UCHAR)((perfCounter.HighPart >> 16) & 0xFF);
    ChainId->Data4[5] = (UCHAR)((sequence >> 16) & 0xFF);
    ChainId->Data4[6] = 0x4A;   // Version marker
    ChainId->Data4[7] = 0xAC;   // "ACT" marker
}
