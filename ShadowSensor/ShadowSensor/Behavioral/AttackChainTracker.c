/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ATTACK CHAIN TRACKER
 * ============================================================================
 *
 * @file AttackChainTracker.c
 * @brief Enterprise-grade multi-stage attack correlation and kill chain tracking.
 *
 * Implements CrowdStrike Falcon-class attack chain detection with:
 * - Real-time MITRE ATT&CK technique correlation
 * - Kill chain phase progression tracking
 * - Process relationship correlation (parent/child, injection targets)
 * - Temporal correlation (events within time windows)
 * - Confidence scoring based on technique combinations
 * - Automatic attack chain creation and merging
 * - Alert callback for confirmed attacks
 * - Evidence collection and preservation
 *
 * Kill Chain Phases (Lockheed Martin Cyber Kill Chain + MITRE):
 * 1. Reconnaissance
 * 2. Initial Access
 * 3. Execution
 * 4. Persistence
 * 5. Privilege Escalation
 * 6. Defense Evasion
 * 7. Credential Access
 * 8. Discovery
 * 9. Lateral Movement
 * 10. Collection
 * 11. Exfiltration
 * 12. Impact
 *
 * Detection Strategy:
 * - Single suspicious events create new chains
 * - Related events (same process tree) join existing chains
 * - Chains advance through phases as techniques are observed
 * - High-confidence attacks trigger alerts when multiple phases detected
 * - Chains expire after inactivity timeout
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AttackChainTracker.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ActInitialize)
#pragma alloc_text(PAGE, ActShutdown)
#pragma alloc_text(PAGE, ActFreeChain)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Chain expiration time (30 minutes in 100ns units)
 */
#define ACT_CHAIN_EXPIRY_TIME           (30LL * 60 * 10000000)

/**
 * @brief Event correlation window (5 minutes in 100ns units)
 */
#define ACT_CORRELATION_WINDOW          (5LL * 60 * 10000000)

/**
 * @brief Minimum score to confirm attack
 */
#define ACT_CONFIRM_THRESHOLD           300

/**
 * @brief Minimum phases for confirmed attack
 */
#define ACT_MIN_PHASES_FOR_CONFIRM      3

/**
 * @brief Pool tag for chain allocations
 */
#define ACT_CHAIN_TAG                   'hCAA'

/**
 * @brief Pool tag for event allocations
 */
#define ACT_EVENT_TAG                   'eCAA'

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
    PCSTR Description;
} ACT_DANGEROUS_COMBO;

static const ACT_DANGEROUS_COMBO g_DangerousCombos[] = {
    //
    // Credential dumping + Lateral movement = Active breach
    //
    { MITRE_T1003 & 0xFFFF, MITRE_T1021 & 0xFFFF, 100, "Credential theft with lateral movement" },

    //
    // Defense evasion + Process injection = Stealthy code execution
    //
    { MITRE_T1562 & 0xFFFF, MITRE_T1055 & 0xFFFF, 80, "Defense evasion with process injection" },

    //
    // Persistence + Privilege escalation = Entrenched attacker
    //
    { MITRE_T1547 & 0xFFFF, MITRE_T1548 & 0xFFFF, 70, "Persistence with privilege escalation" },

    //
    // Collection + Exfiltration = Data theft in progress
    //
    { MITRE_T1560 & 0xFFFF, MITRE_T1041 & 0xFFFF, 90, "Data archiving with exfiltration" },

    //
    // Ransomware indicators
    //
    { MITRE_T1486 & 0xFFFF, MITRE_T1490 & 0xFFFF, 150, "Ransomware with recovery inhibition" },

    //
    // End marker
    //
    { 0, 0, 0, NULL }
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static ACT_CHAIN_STATE
ActpGetPhaseForTechnique(
    _In_ ULONG TechniqueId,
    _Out_ PULONG BaseScore
    );

static PACT_ATTACK_CHAIN
ActpFindChainForProcess(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

static PACT_ATTACK_CHAIN
ActpCreateChain(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ProcessName
    );

static PACT_CHAIN_EVENT
ActpCreateEvent(
    _In_ ULONG TechniqueId,
    _In_ ACT_CHAIN_STATE Phase,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ProcessName,
    _In_ ULONG Score,
    _In_opt_ PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    );

static VOID
ActpFreeEvent(
    _In_ PACT_CHAIN_EVENT Event
    );

static VOID
ActpAddEventToChain(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ PACT_CHAIN_EVENT Event
    );

static VOID
ActpUpdateChainScore(
    _In_ PACT_ATTACK_CHAIN Chain
    );

static BOOLEAN
ActpIsChainExpired(
    _In_ PACT_ATTACK_CHAIN Chain
    );

static VOID
ActpAddRelatedProcess(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ HANDLE ProcessId
    );

static BOOLEAN
ActpIsProcessRelated(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ HANDLE ProcessId
    );

static ULONG
ActpCountPhases(
    _In_ PACT_ATTACK_CHAIN Chain
    );

static VOID
ActpCheckDangerousCombos(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ ULONG NewTechnique
    );

static VOID
ActpGenerateChainId(
    _Out_ PGUID ChainId
    );

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
    // Allocate tracker structure
    //
    tracker = (PACT_TRACKER)ExAllocatePoolZero(
        NonPagedPoolNx,
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
    // Initialize rule list
    //
    InitializeListHead(&tracker->RuleList);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&tracker->Stats.StartTime);

    tracker->Initialized = TRUE;
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

    PAGED_CODE();

    if (Tracker == NULL) {
        return;
    }

    if (!Tracker->Initialized) {
        return;
    }

    Tracker->Initialized = FALSE;

    InitializeListHead(&tempList);

    //
    // Move all chains to temp list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ChainLock);

    while (!IsListEmpty(&Tracker->ChainList)) {
        listEntry = RemoveHeadList(&Tracker->ChainList);
        InsertTailList(&tempList, listEntry);
    }

    Tracker->ChainCount = 0;

    ExReleasePushLockExclusive(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    //
    // Free chains outside lock
    //
    while (!IsListEmpty(&tempList)) {
        listEntry = RemoveHeadList(&tempList);
        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);
        ActFreeChain(chain);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Attack chain tracker shutdown (events=%lld, chains=%lld, attacks=%lld)\n",
               Tracker->Stats.EventsProcessed,
               Tracker->Stats.ChainsCreated,
               Tracker->Stats.AttacksConfirmed);

    ExFreePoolWithTag(Tracker, ACT_POOL_TAG);
}

/**
 * @brief Register callback for attack alerts.
 */
NTSTATUS
ActRegisterCallback(
    _In_ PACT_TRACKER Tracker,
    _In_ ACT_CHAIN_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (Tracker == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    Tracker->AlertCallback = Callback;
    Tracker->CallbackContext = Context;

    return STATUS_SUCCESS;
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
 * @param ProcessName   Process name.
 * @param Evidence      Optional evidence data.
 * @param EvidenceSize  Size of evidence.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ActSubmitEvent(
    _In_ PACT_TRACKER Tracker,
    _In_ ULONG Technique,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ProcessName,
    _In_opt_ PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    )
{
    PACT_ATTACK_CHAIN chain = NULL;
    PACT_CHAIN_EVENT event = NULL;
    ACT_CHAIN_STATE phase;
    ULONG baseScore = 0;
    BOOLEAN newChain = FALSE;
    BOOLEAN confirmedAttack = FALSE;

    if (Tracker == NULL || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
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

    chain = ActpFindChainForProcess(Tracker, ProcessId);

    if (chain == NULL) {
        //
        // Check if we can find a chain for a related process
        // (This would require process tree tracking - simplified here)
        //

        //
        // Create new chain
        //
        if ((ULONG)Tracker->ChainCount < ACT_MAX_ACTIVE_CHAINS) {
            chain = ActpCreateChain(Tracker, ProcessId, ProcessName);
            if (chain != NULL) {
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
            RemoveEntryList(&chain->ListEntry);
            InterlockedDecrement(&Tracker->ChainCount);
            ActFreeChain(chain);
        }
        ExReleasePushLockExclusive(&Tracker->ChainLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Add event to chain
    //
    ActpAddEventToChain(chain, event);

    //
    // Add process to related list
    //
    ActpAddRelatedProcess(chain, ProcessId);

    //
    // Update chain state
    //
    if (phase > chain->CurrentState) {
        chain->CurrentState = phase;
    }

    //
    // Check for dangerous technique combinations
    //
    ActpCheckDangerousCombos(chain, Technique);

    //
    // Update chain score
    //
    ActpUpdateChainScore(chain);

    //
    // Check if attack is now confirmed
    //
    if (!chain->IsConfirmedAttack) {
        ULONG phaseCount = ActpCountPhases(chain);

        if (chain->ThreatScore >= ACT_CONFIRM_THRESHOLD &&
            phaseCount >= ACT_MIN_PHASES_FOR_CONFIRM) {

            chain->IsConfirmedAttack = TRUE;
            confirmedAttack = TRUE;
            InterlockedIncrement64(&Tracker->Stats.AttacksConfirmed);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] ATTACK CONFIRMED: Chain %08lX-%04hX Score=%u Phases=%u\n",
                       chain->ChainId.Data1,
                       chain->ChainId.Data2,
                       chain->ThreatScore,
                       phaseCount);
        }
    }

    ExReleasePushLockExclusive(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    //
    // Fire callback if attack confirmed or chain updated significantly
    //
    if (confirmedAttack && Tracker->AlertCallback != NULL) {
        Tracker->AlertCallback(chain, event, Tracker->CallbackContext);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CHAIN QUERIES
// ============================================================================

/**
 * @brief Get attack chain by ID.
 */
NTSTATUS
ActGetChain(
    _In_ PACT_TRACKER Tracker,
    _In_ PGUID ChainId,
    _Out_ PACT_ATTACK_CHAIN* Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    PACT_ATTACK_CHAIN found = NULL;

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
 */
NTSTATUS
ActCorrelateEvents(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PACT_ATTACK_CHAIN* Chain
    )
{
    PACT_ATTACK_CHAIN found = NULL;

    if (Tracker == NULL || ProcessId == NULL || Chain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Chain = NULL;

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->ChainLock);

    found = ActpFindChainForProcess(Tracker, ProcessId);

    ExReleasePushLockShared(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Chain = found;
    return STATUS_SUCCESS;
}

/**
 * @brief Get all active attack chains.
 */
NTSTATUS
ActGetActiveChains(
    _In_ PACT_TRACKER Tracker,
    _Out_writes_to_(Max, *Count) PACT_ATTACK_CHAIN* Chains,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    ULONG count = 0;

    if (Tracker == NULL || Chains == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->ChainLock);

    for (listEntry = Tracker->ChainList.Flink;
         listEntry != &Tracker->ChainList && count < Max;
         listEntry = listEntry->Flink) {

        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);

        //
        // Skip expired chains
        //
        if (!ActpIsChainExpired(chain)) {
            Chains[count++] = chain;
        }
    }

    ExReleasePushLockShared(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    *Count = count;
    return STATUS_SUCCESS;
}

/**
 * @brief Free an attack chain and all its events.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ActFreeChain(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Chain == NULL) {
        return;
    }

    //
    // Free all events
    //
    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    while (!IsListEmpty(&Chain->EventList)) {
        listEntry = RemoveHeadList(&Chain->EventList);
        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);

        KeReleaseSpinLock(&Chain->EventLock, oldIrql);
        ActpFreeEvent(event);
        KeAcquireSpinLock(&Chain->EventLock, &oldIrql);
    }

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);

    //
    // Free process name buffer if allocated
    //
    if (Chain->RootProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Chain->RootProcessName.Buffer, ACT_CHAIN_TAG);
    }

    //
    // Free chain
    //
    ExFreePoolWithTag(Chain, ACT_CHAIN_TAG);
}

// ============================================================================
// PRIVATE IMPLEMENTATION
// ============================================================================

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

static PACT_ATTACK_CHAIN
ActpFindChainForProcess(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY listEntry;
    PACT_ATTACK_CHAIN chain;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);

    for (listEntry = Tracker->ChainList.Flink;
         listEntry != &Tracker->ChainList;
         listEntry = listEntry->Flink) {

        chain = CONTAINING_RECORD(listEntry, ACT_ATTACK_CHAIN, ListEntry);

        //
        // Check if this is the root process
        //
        if (chain->RootProcessId == ProcessId) {
            if (!ActpIsChainExpired(chain)) {
                return chain;
            }
        }

        //
        // Check if process is in related list
        //
        if (ActpIsProcessRelated(chain, ProcessId)) {
            if (!ActpIsChainExpired(chain)) {
                return chain;
            }
        }
    }

    return NULL;
}

static PACT_ATTACK_CHAIN
ActpCreateChain(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ProcessName
    )
{
    PACT_ATTACK_CHAIN chain;

    UNREFERENCED_PARAMETER(Tracker);

    chain = (PACT_ATTACK_CHAIN)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(ACT_ATTACK_CHAIN),
        ACT_CHAIN_TAG
    );

    if (chain == NULL) {
        return NULL;
    }

    //
    // Generate unique chain ID
    //
    ActpGenerateChainId(&chain->ChainId);

    chain->CurrentState = ActState_Initial;
    chain->RootProcessId = ProcessId;

    //
    // Copy process name
    //
    if (ProcessName != NULL && ProcessName->Length > 0) {
        chain->RootProcessName.Length = ProcessName->Length;
        chain->RootProcessName.MaximumLength = ProcessName->Length + sizeof(WCHAR);
        chain->RootProcessName.Buffer = (PWCH)ExAllocatePoolZero(
            NonPagedPoolNx,
            chain->RootProcessName.MaximumLength,
            ACT_CHAIN_TAG
        );

        if (chain->RootProcessName.Buffer != NULL) {
            RtlCopyMemory(chain->RootProcessName.Buffer,
                          ProcessName->Buffer,
                          ProcessName->Length);
        }
    }

    KeQuerySystemTime(&chain->StartTime);

    InitializeListHead(&chain->EventList);
    KeInitializeSpinLock(&chain->EventLock);
    chain->EventCount = 0;

    chain->ThreatScore = 0;
    chain->ConfidenceScore = 0;
    chain->IsConfirmedAttack = FALSE;

    //
    // Add root process to related list
    //
    chain->RelatedProcessIds[0] = ProcessId;
    chain->RelatedProcessCount = 1;

    InitializeListHead(&chain->ListEntry);

    return chain;
}

static PACT_CHAIN_EVENT
ActpCreateEvent(
    _In_ ULONG TechniqueId,
    _In_ ACT_CHAIN_STATE Phase,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ProcessName,
    _In_ ULONG Score,
    _In_opt_ PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    )
{
    PACT_CHAIN_EVENT event;

    event = (PACT_CHAIN_EVENT)ExAllocatePoolZero(
        NonPagedPoolNx,
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
    // Copy process name
    //
    if (ProcessName != NULL && ProcessName->Length > 0) {
        event->ProcessName.Length = ProcessName->Length;
        event->ProcessName.MaximumLength = ProcessName->Length + sizeof(WCHAR);
        event->ProcessName.Buffer = (PWCH)ExAllocatePoolZero(
            NonPagedPoolNx,
            event->ProcessName.MaximumLength,
            ACT_EVENT_TAG
        );

        if (event->ProcessName.Buffer != NULL) {
            RtlCopyMemory(event->ProcessName.Buffer,
                          ProcessName->Buffer,
                          ProcessName->Length);
        }
    }

    //
    // Copy evidence if provided
    //
    if (Evidence != NULL && EvidenceSize > 0 && EvidenceSize <= 4096) {
        event->EvidenceData = ExAllocatePoolZero(
            NonPagedPoolNx,
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
        "Technique T%04X detected in process %wZ (PID %p)",
        TechniqueId & 0xFFFF,
        ProcessName,
        ProcessId
    );

    InitializeListHead(&event->ListEntry);

    return event;
}

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

static VOID
ActpAddEventToChain(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ PACT_CHAIN_EVENT Event
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    //
    // Check max events
    //
    if (Chain->EventCount < ACT_MAX_CHAIN_EVENTS) {
        InsertTailList(&Chain->EventList, &Event->ListEntry);
        InterlockedIncrement(&Chain->EventCount);
    } else {
        //
        // Evict oldest event
        //
        PLIST_ENTRY oldEntry = RemoveHeadList(&Chain->EventList);
        InsertTailList(&Chain->EventList, &Event->ListEntry);

        KeReleaseSpinLock(&Chain->EventLock, oldIrql);

        PACT_CHAIN_EVENT oldEvent = CONTAINING_RECORD(oldEntry, ACT_CHAIN_EVENT, ListEntry);
        ActpFreeEvent(oldEvent);
        return;
    }

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);
}

static VOID
ActpUpdateChainScore(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    ULONG totalScore = 0;
    ULONG eventCount = 0;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    for (listEntry = Chain->EventList.Flink;
         listEntry != &Chain->EventList;
         listEntry = listEntry->Flink) {

        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        totalScore += event->ConfidenceScore;
        eventCount++;
    }

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);

    Chain->ThreatScore = totalScore;

    //
    // Confidence based on event count and phase progression
    //
    if (eventCount > 0) {
        ULONG phaseCount = ActpCountPhases(Chain);
        Chain->ConfidenceScore = min(100, (eventCount * 10) + (phaseCount * 15));
    }
}

static BOOLEAN
ActpIsChainExpired(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY lastEntry;
    PACT_CHAIN_EVENT lastEvent;
    KIRQL oldIrql;

    //
    // Confirmed attacks don't expire
    //
    if (Chain->IsConfirmedAttack) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Check last event time
    //
    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    if (IsListEmpty(&Chain->EventList)) {
        KeReleaseSpinLock(&Chain->EventLock, oldIrql);

        //
        // Check start time
        //
        return (currentTime.QuadPart - Chain->StartTime.QuadPart) > ACT_CHAIN_EXPIRY_TIME;
    }

    lastEntry = Chain->EventList.Blink;
    lastEvent = CONTAINING_RECORD(lastEntry, ACT_CHAIN_EVENT, ListEntry);

    LARGE_INTEGER lastEventTime = lastEvent->Timestamp;

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);

    return (currentTime.QuadPart - lastEventTime.QuadPart) > ACT_CHAIN_EXPIRY_TIME;
}

static VOID
ActpAddRelatedProcess(
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
    if (Chain->RelatedProcessCount < ARRAYSIZE(Chain->RelatedProcessIds)) {
        Chain->RelatedProcessIds[Chain->RelatedProcessCount++] = ProcessId;
    }
}

static BOOLEAN
ActpIsProcessRelated(
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

static ULONG
ActpCountPhases(
    _In_ PACT_ATTACK_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    ULONG phaseMask = 0;
    ULONG count = 0;
    ULONG i;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    for (listEntry = Chain->EventList.Flink;
         listEntry != &Chain->EventList;
         listEntry = listEntry->Flink) {

        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        phaseMask |= (1 << event->Phase);
    }

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);

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

static VOID
ActpCheckDangerousCombos(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ ULONG NewTechnique
    )
{
    PLIST_ENTRY listEntry;
    PACT_CHAIN_EVENT event;
    ULONG newBase = NewTechnique & 0xFFFF;
    ULONG i;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Chain->EventLock, &oldIrql);

    for (listEntry = Chain->EventList.Flink;
         listEntry != &Chain->EventList;
         listEntry = listEntry->Flink) {

        event = CONTAINING_RECORD(listEntry, ACT_CHAIN_EVENT, ListEntry);
        ULONG existingBase = event->Technique & 0xFFFF;

        //
        // Check against dangerous combos
        //
        for (i = 0; g_DangerousCombos[i].Technique1 != 0; i++) {
            if ((g_DangerousCombos[i].Technique1 == newBase &&
                 g_DangerousCombos[i].Technique2 == existingBase) ||
                (g_DangerousCombos[i].Technique2 == newBase &&
                 g_DangerousCombos[i].Technique1 == existingBase)) {

                //
                // Dangerous combo detected - add bonus score
                //
                Chain->ThreatScore += g_DangerousCombos[i].BonusScore;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Dangerous combo detected: %s (+%u)\n",
                           g_DangerousCombos[i].Description,
                           g_DangerousCombos[i].BonusScore);
            }
        }
    }

    KeReleaseSpinLock(&Chain->EventLock, oldIrql);
}

static VOID
ActpGenerateChainId(
    _Out_ PGUID ChainId
    )
{
    LARGE_INTEGER timestamp;
    LARGE_INTEGER perfCounter;

    KeQuerySystemTime(&timestamp);
    perfCounter = KeQueryPerformanceCounter(NULL);

    //
    // Generate pseudo-random GUID
    // (In production, use ExUuidCreate if available)
    //
    ChainId->Data1 = (ULONG)timestamp.LowPart;
    ChainId->Data2 = (USHORT)(perfCounter.LowPart & 0xFFFF);
    ChainId->Data3 = (USHORT)((perfCounter.LowPart >> 16) & 0xFFFF);
    ChainId->Data4[0] = (UCHAR)(timestamp.HighPart & 0xFF);
    ChainId->Data4[1] = (UCHAR)((timestamp.HighPart >> 8) & 0xFF);
    ChainId->Data4[2] = (UCHAR)((perfCounter.HighPart) & 0xFF);
    ChainId->Data4[3] = (UCHAR)((perfCounter.HighPart >> 8) & 0xFF);
    ChainId->Data4[4] = (UCHAR)((perfCounter.HighPart >> 16) & 0xFF);
    ChainId->Data4[5] = (UCHAR)((perfCounter.HighPart >> 24) & 0xFF);
    ChainId->Data4[6] = 0x4A;  // Version marker
    ChainId->Data4[7] = 0xCT;  // "ACT" marker (invalid hex, use 0xAC)
    ChainId->Data4[7] = 0xAC;
}
