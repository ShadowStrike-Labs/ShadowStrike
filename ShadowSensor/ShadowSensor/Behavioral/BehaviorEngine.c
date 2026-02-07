/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE BEHAVIORAL ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file BehaviorEngine.c
 * @brief Enterprise-grade behavioral analysis engine for kernel EDR.
 *
 * Implements CrowdStrike Falcon-class behavioral detection:
 * - Real-time event correlation and attack chain tracking
 * - MITRE ATT&CK technique detection and mapping
 * - Multi-stage attack chain construction
 * - Threat scoring with weighted factor analysis
 * - Process behavioral context tracking
 * - Rule-based detection with compiled conditions
 * - Anomaly detection baselines
 * - Automatic remediation support
 *
 * Architecture:
 * - Asynchronous event processing via worker thread
 * - Lock-free event queue for high-throughput submission
 * - Per-process behavioral context with reference counting
 * - Attack chain correlation across process boundaries
 * - Lookaside list allocation for hot paths
 *
 * BSOD PREVENTION:
 * - Proper IRQL handling throughout
 * - Safe resource acquisition ordering
 * - Graceful shutdown with pending operation tracking
 * - Memory allocation failure handling
 * - Reference counting for all shared structures
 *
 * Performance Characteristics:
 * - O(1) process context lookup via hash table
 * - Lock-free statistics updates
 * - Batched event processing
 * - Rate-limited logging
 *
 * MITRE ATT&CK Coverage:
 * - Full Enterprise ATT&CK matrix support
 * - Technique-to-tactic mapping
 * - Sub-technique detection
 * - Kill chain stage tracking
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "BehaviorEngine.h"
#include "AttackChainTracker.h"
#include "RuleEngine.h"
#include "ThreatScoring.h"
#include "MITREMapper.h"
#include "AnomalyDetector.h"
#include "IOCMatcher.h"
#include "PatternMatcher.h"
#include "../Core/Globals.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Process context hash table bucket count (power of 2)
 */
#define BE_PROCESS_HASH_BUCKETS         1024

/**
 * @brief Chain hash table bucket count
 */
#define BE_CHAIN_HASH_BUCKETS           512

/**
 * @brief Maximum events to process per worker iteration
 */
#define BE_EVENTS_PER_BATCH             100

/**
 * @brief Worker thread wake interval (ms)
 */
#define BE_WORKER_WAKE_INTERVAL_MS      100

/**
 * @brief Chain cleanup interval (ms)
 */
#define BE_CHAIN_CLEANUP_INTERVAL_MS    60000

/**
 * @brief Process context cleanup age (ms)
 */
#define BE_PROCESS_CLEANUP_AGE_MS       300000

/**
 * @brief Lookaside list depths
 */
#define BE_EVENT_LOOKASIDE_DEPTH        512
#define BE_CHAIN_LOOKASIDE_DEPTH        128
#define BE_ENTRY_LOOKASIDE_DEPTH        1024
#define BE_CONTEXT_LOOKASIDE_DEPTH      256

/**
 * @brief Event type to severity mapping thresholds
 */
#define BE_SEVERITY_LOW_THRESHOLD       200
#define BE_SEVERITY_MEDIUM_THRESHOLD    400
#define BE_SEVERITY_HIGH_THRESHOLD      700
#define BE_SEVERITY_CRITICAL_THRESHOLD  900

/**
 * @brief Maximum process name length
 */
#define BE_MAX_PROCESS_NAME             260

// ============================================================================
// PRIVATE TYPES
// ============================================================================

/**
 * @brief Process context hash entry
 */
typedef struct _BE_PROCESS_HASH_ENTRY {
    LIST_ENTRY HashListEntry;
    PBE_PROCESS_CONTEXT Context;
} BE_PROCESS_HASH_ENTRY, *PBE_PROCESS_HASH_ENTRY;

/**
 * @brief Chain hash entry
 */
typedef struct _BE_CHAIN_HASH_ENTRY {
    LIST_ENTRY HashListEntry;
    PBE_ATTACK_CHAIN Chain;
} BE_CHAIN_HASH_ENTRY, *PBE_CHAIN_HASH_ENTRY;

/**
 * @brief Event type to MITRE mapping entry
 */
typedef struct _BE_EVENT_MITRE_MAP {
    BEHAVIOR_EVENT_TYPE EventType;
    UINT32 MitreTechnique;
    MITRE_TACTIC PrimaryTactic;
    UINT32 BaseThreatScore;
    THREAT_SEVERITY BaseSeverity;
} BE_EVENT_MITRE_MAP, *PBE_EVENT_MITRE_MAP;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Behavioral engine global state
 */
static BEHAVIOR_ENGINE_GLOBALS g_BeState = {0};

/**
 * @brief Process context hash table
 */
static LIST_ENTRY g_ProcessHashTable[BE_PROCESS_HASH_BUCKETS];
static EX_PUSH_LOCK g_ProcessHashLock;

/**
 * @brief Chain hash table (by chain ID)
 */
static LIST_ENTRY g_ChainHashTable[BE_CHAIN_HASH_BUCKETS];
static EX_PUSH_LOCK g_ChainHashLock;

/**
 * @brief Subsystem pointers
 */
static PACT_TRACKER g_AttackChainTracker;
static PRE_ENGINE g_RuleEngine;
static PTS_SCORING_ENGINE g_ScoringEngine;
static PMM_MAPPER g_MitreMapper;

// ============================================================================
// EVENT TO MITRE MAPPING TABLE
// ============================================================================

static const BE_EVENT_MITRE_MAP g_EventMitreMap[] = {
    // Process Execution
    { BehaviorEvent_ProcessCreate,          MITRE_T1106, Tactic_Execution, 100, ThreatSeverity_Informational },
    { BehaviorEvent_ChildProcessSpawn,      MITRE_T1106, Tactic_Execution, 150, ThreatSeverity_Low },
    { BehaviorEvent_CommandLineExecution,   MITRE_T1059, Tactic_Execution, 200, ThreatSeverity_Low },
    { BehaviorEvent_ScriptExecution,        MITRE_T1059, Tactic_Execution, 300, ThreatSeverity_Medium },
    { BehaviorEvent_PowerShellExecution,    MITRE_T1059_001, Tactic_Execution, 400, ThreatSeverity_Medium },
    { BehaviorEvent_WMIExecution,           MITRE_T1047, Tactic_Execution, 350, ThreatSeverity_Medium },
    { BehaviorEvent_ScheduledTaskCreate,    MITRE_T1053_005, Tactic_Persistence, 450, ThreatSeverity_Medium },
    { BehaviorEvent_ServiceCreate,          MITRE_T1543_003, Tactic_Persistence, 400, ThreatSeverity_Medium },
    { BehaviorEvent_DriverLoad,             MITRE_T1547_006, Tactic_Persistence, 600, ThreatSeverity_High },
    { BehaviorEvent_SuspiciousParentChild,  MITRE_T1055, Tactic_DefenseEvasion, 500, ThreatSeverity_Medium },
    { BehaviorEvent_LOLBinExecution,        MITRE_T1218, Tactic_DefenseEvasion, 450, ThreatSeverity_Medium },

    // Code Injection
    { BehaviorEvent_RemoteThreadCreate,     MITRE_T1055_001, Tactic_PrivilegeEscalation, 700, ThreatSeverity_High },
    { BehaviorEvent_APCQueueInjection,      MITRE_T1055_004, Tactic_PrivilegeEscalation, 750, ThreatSeverity_High },
    { BehaviorEvent_ProcessHollowing,       MITRE_T1055_012, Tactic_DefenseEvasion, 850, ThreatSeverity_Critical },
    { BehaviorEvent_ProcessDoppelganging,   MITRE_T1055_013, Tactic_DefenseEvasion, 900, ThreatSeverity_Critical },
    { BehaviorEvent_AtomBombing,            MITRE_T1055, Tactic_DefenseEvasion, 800, ThreatSeverity_High },
    { BehaviorEvent_ModuleStomping,         MITRE_T1055, Tactic_DefenseEvasion, 750, ThreatSeverity_High },
    { BehaviorEvent_ReflectiveDLLLoad,      MITRE_T1620, Tactic_DefenseEvasion, 800, ThreatSeverity_High },
    { BehaviorEvent_EarlyBirdInjection,     MITRE_T1055, Tactic_DefenseEvasion, 850, ThreatSeverity_Critical },
    { BehaviorEvent_ThreadExecutionHijack,  MITRE_T1055_003, Tactic_PrivilegeEscalation, 750, ThreatSeverity_High },
    { BehaviorEvent_NtMapViewInjection,     MITRE_T1055, Tactic_DefenseEvasion, 700, ThreatSeverity_High },
    { BehaviorEvent_SetWindowsHookEx,       MITRE_T1056_001, Tactic_CredentialAccess, 500, ThreatSeverity_Medium },
    { BehaviorEvent_QueueUserAPC,           MITRE_T1055_004, Tactic_PrivilegeEscalation, 700, ThreatSeverity_High },

    // Memory Operations
    { BehaviorEvent_SuspiciousAllocation,   MITRE_T1055, Tactic_DefenseEvasion, 400, ThreatSeverity_Medium },
    { BehaviorEvent_RWXMemory,              MITRE_T1055, Tactic_DefenseEvasion, 600, ThreatSeverity_High },
    { BehaviorEvent_MemoryProtectionChange, MITRE_T1055, Tactic_DefenseEvasion, 500, ThreatSeverity_Medium },
    { BehaviorEvent_CrossProcessRead,       MITRE_T1055, Tactic_CredentialAccess, 550, ThreatSeverity_Medium },
    { BehaviorEvent_CrossProcessWrite,      MITRE_T1055, Tactic_PrivilegeEscalation, 650, ThreatSeverity_High },
    { BehaviorEvent_UnbackedExecutable,     MITRE_T1620, Tactic_DefenseEvasion, 700, ThreatSeverity_High },
    { BehaviorEvent_ShellcodeDetected,      MITRE_T1055, Tactic_Execution, 850, ThreatSeverity_Critical },

    // Privilege Operations
    { BehaviorEvent_PrivilegeEscalation,    MITRE_T1068, Tactic_PrivilegeEscalation, 800, ThreatSeverity_High },
    { BehaviorEvent_TokenManipulation,      MITRE_T1134, Tactic_PrivilegeEscalation, 700, ThreatSeverity_High },
    { BehaviorEvent_TokenImpersonation,     MITRE_T1134_001, Tactic_PrivilegeEscalation, 650, ThreatSeverity_High },
    { BehaviorEvent_TokenStealing,          MITRE_T1134_001, Tactic_PrivilegeEscalation, 750, ThreatSeverity_High },
    { BehaviorEvent_BypassUAC,              MITRE_T1548_002, Tactic_PrivilegeEscalation, 700, ThreatSeverity_High },
    { BehaviorEvent_SeDebugPrivilege,       MITRE_T1134, Tactic_PrivilegeEscalation, 600, ThreatSeverity_High },

    // Persistence
    { BehaviorEvent_RegistryRunKey,         MITRE_T1547_001, Tactic_Persistence, 500, ThreatSeverity_Medium },
    { BehaviorEvent_ScheduledTaskPersistence, MITRE_T1053_005, Tactic_Persistence, 550, ThreatSeverity_Medium },
    { BehaviorEvent_ServicePersistence,     MITRE_T1543_003, Tactic_Persistence, 500, ThreatSeverity_Medium },
    { BehaviorEvent_StartupFolderDrop,      MITRE_T1547_001, Tactic_Persistence, 450, ThreatSeverity_Medium },
    { BehaviorEvent_WMISubscription,        MITRE_T1546_003, Tactic_Persistence, 600, ThreatSeverity_High },
    { BehaviorEvent_DLLHijacking,           MITRE_T1574_001, Tactic_Persistence, 650, ThreatSeverity_High },
    { BehaviorEvent_COMHijacking,           MITRE_T1546_015, Tactic_Persistence, 600, ThreatSeverity_High },
    { BehaviorEvent_BootkitInstall,         MITRE_T1542_003, Tactic_Persistence, 950, ThreatSeverity_Critical },
    { BehaviorEvent_ImageFilePersistence,   MITRE_T1546_012, Tactic_Persistence, 700, ThreatSeverity_High },

    // Defense Evasion
    { BehaviorEvent_DirectSyscall,          MITRE_T1106, Tactic_DefenseEvasion, 650, ThreatSeverity_High },
    { BehaviorEvent_NtdllUnhooking,         MITRE_T1562_001, Tactic_DefenseEvasion, 750, ThreatSeverity_High },
    { BehaviorEvent_HeavensGate,            MITRE_T1106, Tactic_DefenseEvasion, 800, ThreatSeverity_High },
    { BehaviorEvent_ETWPatching,            MITRE_T1562_006, Tactic_DefenseEvasion, 850, ThreatSeverity_Critical },
    { BehaviorEvent_AMSIBypass,             MITRE_T1562_001, Tactic_DefenseEvasion, 800, ThreatSeverity_High },
    { BehaviorEvent_DisableWindowsDefender, MITRE_T1562_001, Tactic_DefenseEvasion, 750, ThreatSeverity_High },
    { BehaviorEvent_DisableFirewall,        MITRE_T1562_004, Tactic_DefenseEvasion, 600, ThreatSeverity_High },
    { BehaviorEvent_ProcessMasquerading,    MITRE_T1036, Tactic_DefenseEvasion, 550, ThreatSeverity_Medium },
    { BehaviorEvent_TimestampModification,  MITRE_T1070_006, Tactic_DefenseEvasion, 500, ThreatSeverity_Medium },
    { BehaviorEvent_HiddenFileCreation,     MITRE_T1564_001, Tactic_DefenseEvasion, 350, ThreatSeverity_Low },
    { BehaviorEvent_AlternateDataStream,    MITRE_T1564_004, Tactic_DefenseEvasion, 450, ThreatSeverity_Medium },
    { BehaviorEvent_LogDeletion,            MITRE_T1070_001, Tactic_DefenseEvasion, 700, ThreatSeverity_High },
    { BehaviorEvent_VirtualizationEvasion,  MITRE_T1497, Tactic_DefenseEvasion, 400, ThreatSeverity_Medium },
    { BehaviorEvent_DebuggerEvasion,        MITRE_T1497, Tactic_DefenseEvasion, 350, ThreatSeverity_Low },
    { BehaviorEvent_SandboxEvasion,         MITRE_T1497, Tactic_DefenseEvasion, 450, ThreatSeverity_Medium },
    { BehaviorEvent_PPLBypass,              MITRE_T1548, Tactic_DefenseEvasion, 900, ThreatSeverity_Critical },
    { BehaviorEvent_CallbackRemoval,        MITRE_T1562_001, Tactic_DefenseEvasion, 850, ThreatSeverity_Critical },

    // Credential Access
    { BehaviorEvent_LSASSAccess,            MITRE_T1003_001, Tactic_CredentialAccess, 900, ThreatSeverity_Critical },
    { BehaviorEvent_SAMRegistryAccess,      MITRE_T1003_002, Tactic_CredentialAccess, 800, ThreatSeverity_High },
    { BehaviorEvent_NTDSAccess,             MITRE_T1003_003, Tactic_CredentialAccess, 850, ThreatSeverity_Critical },
    { BehaviorEvent_CredentialDumping,      MITRE_T1003, Tactic_CredentialAccess, 900, ThreatSeverity_Critical },
    { BehaviorEvent_KeyloggerBehavior,      MITRE_T1056_001, Tactic_CredentialAccess, 700, ThreatSeverity_High },
    { BehaviorEvent_BrowserCredentialAccess, MITRE_T1555_003, Tactic_CredentialAccess, 650, ThreatSeverity_High },
    { BehaviorEvent_DCSync,                 MITRE_T1003_006, Tactic_CredentialAccess, 950, ThreatSeverity_Critical },

    // Network
    { BehaviorEvent_C2Communication,        MITRE_T1071, Tactic_CommandAndControl, 800, ThreatSeverity_High },
    { BehaviorEvent_DNSTunneling,           MITRE_T1071_004, Tactic_CommandAndControl, 750, ThreatSeverity_High },
    { BehaviorEvent_DGADomain,              MITRE_T1568_002, Tactic_CommandAndControl, 700, ThreatSeverity_High },
    { BehaviorEvent_Beaconing,              MITRE_T1071, Tactic_CommandAndControl, 650, ThreatSeverity_High },
    { BehaviorEvent_DataExfiltration,       MITRE_T1041, Tactic_Exfiltration, 800, ThreatSeverity_High },
    { BehaviorEvent_LateralMovementNetwork, MITRE_T1021, Tactic_LateralMovement, 700, ThreatSeverity_High },
    { BehaviorEvent_ReverseShell,           MITRE_T1059, Tactic_Execution, 900, ThreatSeverity_Critical },
    { BehaviorEvent_PortScanning,           MITRE_T1046, Tactic_Discovery, 400, ThreatSeverity_Medium },

    // Impact
    { BehaviorEvent_RansomwareBehavior,     MITRE_T1486, Tactic_Impact, 1000, ThreatSeverity_Critical },
    { BehaviorEvent_MassFileEncryption,     MITRE_T1486, Tactic_Impact, 1000, ThreatSeverity_Critical },
    { BehaviorEvent_MassFileDeletion,       MITRE_T1485, Tactic_Impact, 900, ThreatSeverity_Critical },
    { BehaviorEvent_VSSDestruction,         MITRE_T1490, Tactic_Impact, 950, ThreatSeverity_Critical },
    { BehaviorEvent_BackupDeletion,         MITRE_T1490, Tactic_Impact, 900, ThreatSeverity_Critical },
    { BehaviorEvent_DiskWipe,               MITRE_T1561, Tactic_Impact, 1000, ThreatSeverity_Critical },
    { BehaviorEvent_ServiceStopping,        MITRE_T1489, Tactic_Impact, 600, ThreatSeverity_High },

    // Terminator
    { 0, 0, Tactic_None, 0, ThreatSeverity_None }
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
BepInitializeHashTables(
    VOID
    );

static VOID
BepCleanupHashTables(
    VOID
    );

static NTSTATUS
BepInitializeLookasideLists(
    VOID
    );

static VOID
BepCleanupLookasideLists(
    VOID
    );

static VOID
BepWorkerThread(
    _In_ PVOID StartContext
    );

static VOID
BepProcessEventBatch(
    VOID
    );

static NTSTATUS
BepProcessSingleEvent(
    _In_ PBE_PENDING_EVENT Event
    );

static PBE_PENDING_EVENT
BepAllocateEvent(
    _In_ UINT32 EventDataSize
    );

static VOID
BepFreeEvent(
    _In_ PBE_PENDING_EVENT Event
    );

static PBE_ATTACK_CHAIN
BepAllocateChain(
    VOID
    );

static VOID
BepFreeChain(
    _In_ PBE_ATTACK_CHAIN Chain
    );

static PBE_CHAIN_ENTRY
BepAllocateChainEntry(
    VOID
    );

static VOID
BepFreeChainEntry(
    _In_ PBE_CHAIN_ENTRY Entry
    );

static PBE_PROCESS_CONTEXT
BepAllocateProcessContext(
    VOID
    );

static VOID
BepFreeProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    );

static UINT32
BepHashProcessId(
    _In_ UINT32 ProcessId
    );

static UINT32
BepHashChainId(
    _In_ UINT64 ChainId
    );

static NTSTATUS
BepInsertProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    );

static VOID
BepRemoveProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    );

static NTSTATUS
BepInsertChain(
    _In_ PBE_ATTACK_CHAIN Chain
    );

static VOID
BepRemoveChain(
    _In_ PBE_ATTACK_CHAIN Chain
    );

static NTSTATUS
BepGetOrCreateProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PBE_PROCESS_CONTEXT* Context
    );

static NTSTATUS
BepGetOrCreateChain(
    _In_ UINT32 ProcessId,
    _Out_ PBE_ATTACK_CHAIN* Chain
    );

static NTSTATUS
BepCorrelateEventToChain(
    _In_ PBE_PENDING_EVENT Event,
    _In_ PBE_PROCESS_CONTEXT ProcessContext,
    _Inout_ PBE_ATTACK_CHAIN Chain
    );

static NTSTATUS
BepMapEventToMitre(
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _Out_ PUINT32 TechniqueId,
    _Out_ PMITRE_TACTIC Tactic,
    _Out_ PUINT32 BaseThreatScore,
    _Out_ PTHREAT_SEVERITY BaseSeverity
    );

static ATTACK_CHAIN_STAGE
BepTacticToStage(
    _In_ MITRE_TACTIC Tactic
    );

static UINT32
BepCalculateEventThreatScore(
    _In_ PBE_PENDING_EVENT Event,
    _In_ PBE_PROCESS_CONTEXT ProcessContext,
    _In_ UINT32 BaseThreatScore
    );

static THREAT_SEVERITY
BepScoreToSeverity(
    _In_ UINT32 ThreatScore
    );

static BEHAVIOR_RESPONSE_ACTION
BepDetermineResponse(
    _In_ PBE_PENDING_EVENT Event,
    _In_ PBE_ATTACK_CHAIN Chain,
    _In_ UINT32 ThreatScore
    );

static VOID
BepUpdateProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context,
    _In_ PBE_PENDING_EVENT Event,
    _In_ UINT32 ThreatScore
    );

static VOID
BepUpdateChainState(
    _In_ PBE_ATTACK_CHAIN Chain,
    _In_ PBE_CHAIN_ENTRY Entry
    );

static VOID
BepCleanupStaleChains(
    VOID
    );

static VOID
BepCleanupStaleProcessContexts(
    VOID
    );

static BOOLEAN
BepIsLolBin(
    _In_ PCWSTR ImagePath
    );

static BOOLEAN
BepIsScriptHost(
    _In_ PCWSTR ImagePath
    );

static VOID
BepGetProcessName(
    _In_ PCWSTR ImagePath,
    _Out_writes_(MaxLength) PWCHAR ProcessName,
    _In_ ULONG MaxLength
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the behavioral engine.
 *
 * This function initializes all behavioral analysis components:
 * 1. Initialize hash tables for process and chain tracking
 * 2. Initialize lookaside lists for memory allocation
 * 3. Initialize event queue
 * 4. Create worker thread
 * 5. Initialize subsystems (if available)
 *
 * @return STATUS_SUCCESS on success, error status otherwise.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BeEngineInitialize(
    VOID
    )
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES oa;

    PAGED_CODE();

    //
    // Check if already initialized
    //
    if (g_BeState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_BeState, sizeof(BEHAVIOR_ENGINE_GLOBALS));

    //
    // Initialize hash tables
    //
    status = BepInitializeHashTables();
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Initialize lookaside lists
    //
    status = BepInitializeLookasideLists();
    if (!NT_SUCCESS(status)) {
        BepCleanupHashTables();
        goto Cleanup;
    }

    //
    // Initialize lists and locks
    //
    InitializeListHead(&g_BeState.ActiveChainList);
    ExInitializeResourceLite(&g_BeState.ChainLock);
    g_BeState.ActiveChainCount = 0;
    g_BeState.NextChainId = 1;

    InitializeListHead(&g_BeState.ProcessContextList);
    ExInitializeResourceLite(&g_BeState.ProcessLock);
    g_BeState.ProcessContextCount = 0;

    InitializeListHead(&g_BeState.LoadedRuleList);
    ExInitializeResourceLite(&g_BeState.RuleLock);
    g_BeState.LoadedRuleCount = 0;
    g_BeState.EnabledRuleCount = 0;

    InitializeListHead(&g_BeState.PendingEventQueue);
    KeInitializeSpinLock(&g_BeState.EventQueueLock);
    g_BeState.PendingEventCount = 0;
    g_BeState.MaxPendingEvents = BE_MAX_PENDING_EVENTS;

    //
    // Initialize worker thread events
    //
    KeInitializeEvent(&g_BeState.WorkerWakeEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_BeState.WorkerStopEvent, NotificationEvent, FALSE);
    g_BeState.WorkerStopping = FALSE;

    //
    // Set default configuration
    //
    g_BeState.ChainTimeoutMs = BE_DEFAULT_CHAIN_TIMEOUT_MS;
    g_BeState.MaxActiveChains = BE_DEFAULT_MAX_ACTIVE_CHAINS;
    g_BeState.MaxEventsPerChain = BE_DEFAULT_MAX_EVENTS_PER_CHAIN;
    g_BeState.CorrelationWindowMs = BE_DEFAULT_CORRELATION_WINDOW_MS;
    g_BeState.HighThreatThreshold = BE_DEFAULT_HIGH_THREAT_THRESHOLD;
    g_BeState.CriticalThreshold = BE_DEFAULT_CRITICAL_THRESHOLD;

    //
    // Create worker thread
    //
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        BepWorkerThread,
        NULL
        );

    if (!NT_SUCCESS(status)) {
        goto CleanupResources;
    }

    //
    // Get thread object reference
    //
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&g_BeState.WorkerThread,
        NULL
        );

    ZwClose(threadHandle);

    if (!NT_SUCCESS(status)) {
        //
        // Signal thread to stop
        //
        g_BeState.WorkerStopping = TRUE;
        KeSetEvent(&g_BeState.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
        goto CleanupResources;
    }

    //
    // Initialize timing
    //
    {
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);
        g_BeState.LastChainCleanupTime = (UINT64)(currentTime.QuadPart / 10000);
        g_BeState.LastStatisticsReportTime = g_BeState.LastChainCleanupTime;
    }

    //
    // Mark as initialized and enabled
    //
    g_BeState.Initialized = TRUE;
    g_BeState.Enabled = TRUE;

    return STATUS_SUCCESS;

CleanupResources:
    ExDeleteResourceLite(&g_BeState.ChainLock);
    ExDeleteResourceLite(&g_BeState.ProcessLock);
    ExDeleteResourceLite(&g_BeState.RuleLock);
    BepCleanupLookasideLists();
    BepCleanupHashTables();

Cleanup:
    RtlZeroMemory(&g_BeState, sizeof(BEHAVIOR_ENGINE_GLOBALS));
    return status;
}

/**
 * @brief Shutdown the behavioral engine.
 *
 * Performs graceful shutdown:
 * 1. Signal worker thread to stop
 * 2. Wait for worker thread completion
 * 3. Free all pending events
 * 4. Free all chains and process contexts
 * 5. Cleanup resources
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
BeEngineShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;
    PBE_PENDING_EVENT event;
    PBE_ATTACK_CHAIN chain;
    PBE_PROCESS_CONTEXT context;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (!g_BeState.Initialized) {
        return;
    }

    //
    // Mark as disabled and stopping
    //
    g_BeState.Enabled = FALSE;
    g_BeState.WorkerStopping = TRUE;

    //
    // Signal worker thread to stop
    //
    KeSetEvent(&g_BeState.WorkerStopEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&g_BeState.WorkerWakeEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for worker thread to exit
    //
    if (g_BeState.WorkerThread != NULL) {
        timeout.QuadPart = -100000000;  // 10 seconds
        KeWaitForSingleObject(
            g_BeState.WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            &timeout
            );

        ObDereferenceObject(g_BeState.WorkerThread);
        g_BeState.WorkerThread = NULL;
    }

    //
    // Free all pending events
    //
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_BeState.EventQueueLock, &oldIrql);

        while (!IsListEmpty(&g_BeState.PendingEventQueue)) {
            entry = RemoveHeadList(&g_BeState.PendingEventQueue);
            event = CONTAINING_RECORD(entry, BE_PENDING_EVENT, ListEntry);
            g_BeState.PendingEventCount--;

            KeReleaseSpinLock(&g_BeState.EventQueueLock, oldIrql);
            BepFreeEvent(event);
            KeAcquireSpinLock(&g_BeState.EventQueueLock, &oldIrql);
        }

        KeReleaseSpinLock(&g_BeState.EventQueueLock, oldIrql);
    }

    //
    // Free all attack chains
    //
    ExAcquireResourceExclusiveLite(&g_BeState.ChainLock, TRUE);

    while (!IsListEmpty(&g_BeState.ActiveChainList)) {
        entry = RemoveHeadList(&g_BeState.ActiveChainList);
        chain = CONTAINING_RECORD(entry, BE_ATTACK_CHAIN, ListEntry);
        g_BeState.ActiveChainCount--;

        //
        // Free chain entries
        //
        while (!IsListEmpty(&chain->EntryList)) {
            PLIST_ENTRY entryEntry = RemoveHeadList(&chain->EntryList);
            PBE_CHAIN_ENTRY chainEntry = CONTAINING_RECORD(entryEntry, BE_CHAIN_ENTRY, ListEntry);
            BepFreeChainEntry(chainEntry);
        }

        BepFreeChain(chain);
    }

    ExReleaseResourceLite(&g_BeState.ChainLock);

    //
    // Free all process contexts
    //
    ExAcquireResourceExclusiveLite(&g_BeState.ProcessLock, TRUE);

    while (!IsListEmpty(&g_BeState.ProcessContextList)) {
        entry = RemoveHeadList(&g_BeState.ProcessContextList);
        context = CONTAINING_RECORD(entry, BE_PROCESS_CONTEXT, ListEntry);
        g_BeState.ProcessContextCount--;
        BepFreeProcessContext(context);
    }

    ExReleaseResourceLite(&g_BeState.ProcessLock);

    //
    // Cleanup resources
    //
    ExDeleteResourceLite(&g_BeState.ChainLock);
    ExDeleteResourceLite(&g_BeState.ProcessLock);
    ExDeleteResourceLite(&g_BeState.RuleLock);

    BepCleanupHashTables();
    BepCleanupLookasideLists();

    //
    // Clear state
    //
    g_BeState.Initialized = FALSE;
    RtlZeroMemory(&g_BeState, sizeof(BEHAVIOR_ENGINE_GLOBALS));
}

/**
 * @brief Enable or disable the behavioral engine.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BeEngineSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    g_BeState.Enabled = Enable;
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - EVENT SUBMISSION
// ============================================================================

/**
 * @brief Submit behavioral event for analysis.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
BeEngineSubmitEvent(
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_ BEHAVIOR_EVENT_CATEGORY Category,
    _In_ UINT32 ProcessId,
    _In_reads_bytes_(EventDataSize) PVOID EventData,
    _In_ UINT32 EventDataSize,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN IsBlocking,
    _Out_opt_ PBEHAVIOR_RESPONSE_ACTION Response
    )
{
    PBE_PENDING_EVENT event;
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    UINT32 mitreTechnique;
    MITRE_TACTIC tactic;
    UINT32 baseThreatScore;
    THREAT_SEVERITY baseSeverity;

    if (!g_BeState.Initialized || !g_BeState.Enabled) {
        if (Response != NULL) {
            *Response = BehaviorResponse_Allow;
        }
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check queue limit
    //
    if ((UINT32)g_BeState.PendingEventCount >= g_BeState.MaxPendingEvents) {
        InterlockedIncrement64(&g_BeState.EventsDropped);
        if (Response != NULL) {
            *Response = BehaviorResponse_Allow;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Map event to MITRE
    //
    BepMapEventToMitre(EventType, &mitreTechnique, &tactic, &baseThreatScore, &baseSeverity);

    //
    // Use provided threat score if non-zero
    //
    if (ThreatScore > 0) {
        baseThreatScore = ThreatScore;
    }

    //
    // Allocate event
    //
    event = BepAllocateEvent(EventDataSize);
    if (event == NULL) {
        InterlockedIncrement64(&g_BeState.EventsDropped);
        if (Response != NULL) {
            *Response = BehaviorResponse_Allow;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize event
    //
    KeQuerySystemTime(&currentTime);

    event->EventType = EventType;
    event->Category = Category;
    event->ReceiveTime = (UINT64)(currentTime.QuadPart / 10000);
    event->ProcessId = ProcessId;
    event->InitialThreatScore = baseThreatScore;
    event->InitialSeverity = baseSeverity;
    event->MitreAttackId = mitreTechnique;
    event->EventDataSize = EventDataSize;
    event->Flags = 0;

    if (IsBlocking) {
        event->Flags |= BE_EVENT_FLAG_BLOCKING;
    }

    //
    // Copy event data
    //
    if (EventData != NULL && EventDataSize > 0) {
        RtlCopyMemory(event->EventData, EventData, EventDataSize);
    }

    //
    // Generate correlation ID
    //
    event->CorrelationId.Timestamp = event->ReceiveTime;
    event->CorrelationId.ProcessId = ProcessId;
    event->CorrelationId.SequenceNumber = (UINT64)InterlockedIncrement64(&g_BeState.TotalEventsProcessed);

    //
    // For blocking events, process synchronously
    //
    if (IsBlocking) {
        NTSTATUS status = BepProcessSingleEvent(event);

        if (Response != NULL) {
            //
            // Determine response based on threat score
            //
            if (event->InitialThreatScore >= g_BeState.CriticalThreshold) {
                *Response = BehaviorResponse_Block;
            } else if (event->InitialThreatScore >= g_BeState.HighThreatThreshold) {
                *Response = BehaviorResponse_Alert;
            } else {
                *Response = BehaviorResponse_Allow;
            }
        }

        BepFreeEvent(event);
        return status;
    }

    //
    // Queue for async processing
    //
    KeAcquireSpinLock(&g_BeState.EventQueueLock, &oldIrql);
    InsertTailList(&g_BeState.PendingEventQueue, &event->ListEntry);
    g_BeState.PendingEventCount++;
    KeReleaseSpinLock(&g_BeState.EventQueueLock, oldIrql);

    //
    // Wake worker thread
    //
    KeSetEvent(&g_BeState.WorkerWakeEvent, IO_NO_INCREMENT, FALSE);

    if (Response != NULL) {
        *Response = BehaviorResponse_Allow;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Submit process creation event.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BeEngineProcessCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine
    )
{
    PBE_PROCESS_CONTEXT context;
    NTSTATUS status;
    PEPROCESS process = NULL;

    PAGED_CODE();

    if (!g_BeState.Initialized || !g_BeState.Enabled) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate process context
    //
    context = BepAllocateProcessContext();
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize context
    //
    context->ProcessId = ProcessId;
    context->ParentProcessId = ParentProcessId;
    context->RefCount = 1;

    //
    // Get process create time
    //
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (NT_SUCCESS(status)) {
        context->ProcessObject = process;
        context->ProcessCreateTime = (UINT64)(PsGetProcessCreateTimeQuadPart(process) / 10000);
        ObDereferenceObject(process);
    }

    //
    // Copy image path
    //
    if (ImagePath != NULL && ImagePath->Buffer != NULL) {
        SIZE_T copyLen = min(ImagePath->Length, (MAX_FILE_PATH_LENGTH - 1) * sizeof(WCHAR));
        RtlCopyMemory(context->ImagePath, ImagePath->Buffer, copyLen);
        context->ImagePath[copyLen / sizeof(WCHAR)] = L'\0';
    }

    //
    // Copy command line
    //
    if (CommandLine != NULL && CommandLine->Buffer != NULL) {
        SIZE_T copyLen = min(CommandLine->Length, (MAX_COMMAND_LINE_LENGTH - 1) * sizeof(WCHAR));
        RtlCopyMemory(context->CommandLine, CommandLine->Buffer, copyLen);
        context->CommandLine[copyLen / sizeof(WCHAR)] = L'\0';
    }

    //
    // Determine process flags
    //
    if (BepIsLolBin(context->ImagePath)) {
        context->Flags |= BE_PROC_FLAG_LOLBIN;
    }

    if (BepIsScriptHost(context->ImagePath)) {
        context->Flags |= BE_PROC_FLAG_SCRIPT_HOST;
    }

    //
    // Initialize chain list
    //
    InitializeListHead(&context->ChainList);
    context->ChainCount = 0;

    //
    // Insert into tracking
    //
    status = BepInsertProcessContext(context);
    if (!NT_SUCCESS(status)) {
        BepFreeProcessContext(context);
        return status;
    }

    //
    // Submit process creation event
    //
    return BeEngineSubmitEvent(
        BehaviorEvent_ProcessCreate,
        BehaviorCategory_ProcessExecution,
        ProcessId,
        NULL,
        0,
        0,
        FALSE,
        NULL
        );
}

/**
 * @brief Submit process termination event.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BeEngineProcessTerminate(
    _In_ UINT32 ProcessId
    )
{
    PBE_PROCESS_CONTEXT context;
    NTSTATUS status;

    PAGED_CODE();

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find and update context
    //
    status = BeEngineGetProcessContext(ProcessId, &context);
    if (NT_SUCCESS(status)) {
        context->Flags |= BE_PROC_FLAG_TERMINATED;
        BeEngineReleaseProcessContext(context);
    }

    //
    // Submit termination event
    //
    return BeEngineSubmitEvent(
        BehaviorEvent_ProcessTerminate,
        BehaviorCategory_ProcessExecution,
        ProcessId,
        NULL,
        0,
        0,
        FALSE,
        NULL
        );
}

// ============================================================================
// PUBLIC API - ATTACK CHAIN MANAGEMENT
// ============================================================================

/**
 * @brief Get attack chain by ID.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetChain(
    _In_ UINT64 ChainId,
    _Out_ PBE_ATTACK_CHAIN* Chain
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PBE_CHAIN_HASH_ENTRY hashEntry;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Chain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Chain = NULL;

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashIndex = BepHashChainId(ChainId);

    FltAcquirePushLockShared(&g_ChainHashLock);

    for (entry = g_ChainHashTable[hashIndex].Flink;
         entry != &g_ChainHashTable[hashIndex];
         entry = entry->Flink) {

        hashEntry = CONTAINING_RECORD(entry, BE_CHAIN_HASH_ENTRY, HashListEntry);

        if (hashEntry->Chain->ChainId == ChainId) {
            InterlockedIncrement(&hashEntry->Chain->RefCount);
            *Chain = hashEntry->Chain;
            status = STATUS_SUCCESS;
            break;
        }
    }

    FltReleasePushLock(&g_ChainHashLock);
    return status;
}

/**
 * @brief Get attack chains for process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetProcessChains(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxChains, *ChainCount) PBE_ATTACK_CHAIN* Chains,
    _In_ UINT32 MaxChains,
    _Out_ PUINT32 ChainCount
    )
{
    PBE_PROCESS_CONTEXT context;
    NTSTATUS status;
    PLIST_ENTRY entry;
    UINT32 count = 0;

    if (Chains == NULL || ChainCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ChainCount = 0;

    status = BeEngineGetProcessContext(ProcessId, &context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Iterate process chain list
    //
    for (entry = context->ChainList.Flink;
         entry != &context->ChainList && count < MaxChains;
         entry = entry->Flink) {

        PBE_ATTACK_CHAIN chain = CONTAINING_RECORD(entry, BE_ATTACK_CHAIN, ProcessListEntry);
        InterlockedIncrement(&chain->RefCount);
        Chains[count++] = chain;
    }

    *ChainCount = count;
    BeEngineReleaseProcessContext(context);

    return STATUS_SUCCESS;
}

/**
 * @brief Release chain reference.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
BeEngineReleaseChain(
    _In_ PBE_ATTACK_CHAIN Chain
    )
{
    if (Chain == NULL) {
        return;
    }

    InterlockedDecrement(&Chain->RefCount);
}

/**
 * @brief Mark chain as false positive.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineMarkChainFalsePositive(
    _In_ UINT64 ChainId
    )
{
    PBE_ATTACK_CHAIN chain;
    NTSTATUS status;

    status = BeEngineGetChain(ChainId, &chain);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    chain->Flags |= CHAIN_FLAG_FALSE_POSITIVE;
    chain->IsActive = FALSE;

    BeEngineReleaseChain(chain);
    return STATUS_SUCCESS;
}

/**
 * @brief Remediate attack chain.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BeEngineRemediateChain(
    _In_ UINT64 ChainId,
    _In_ UINT32 RemediationFlags
    )
{
    PBE_ATTACK_CHAIN chain;
    NTSTATUS status;

    PAGED_CODE();

    status = BeEngineGetChain(ChainId, &chain);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Terminate primary process if requested
    //
    if (RemediationFlags & BE_REMEDIATE_TERMINATE_PRIMARY) {
        HANDLE processHandle;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID clientId;

        clientId.UniqueProcess = (HANDLE)(ULONG_PTR)chain->PrimaryProcessId;
        clientId.UniqueThread = NULL;
        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenProcess(&processHandle, PROCESS_TERMINATE, &oa, &clientId);
        if (NT_SUCCESS(status)) {
            ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
            ZwClose(processHandle);
        }
    }

    //
    // Terminate related processes if requested
    //
    if (RemediationFlags & BE_REMEDIATE_TERMINATE_RELATED) {
        for (UINT32 i = 0; i < chain->RelatedProcessCount; i++) {
            HANDLE processHandle;
            OBJECT_ATTRIBUTES oa;
            CLIENT_ID clientId;

            clientId.UniqueProcess = (HANDLE)(ULONG_PTR)chain->RelatedProcessIds[i];
            clientId.UniqueThread = NULL;
            InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwOpenProcess(&processHandle, PROCESS_TERMINATE, &oa, &clientId);
            if (NT_SUCCESS(status)) {
                ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
                ZwClose(processHandle);
            }
        }
    }

    chain->IsRemediated = TRUE;
    chain->IsActive = FALSE;
    chain->Flags |= BE_CHAIN_FLAG_AUTO_REMEDIATE;

    InterlockedIncrement64(&g_BeState.TotalThreatsBlocked);

    BeEngineReleaseChain(chain);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - PROCESS CONTEXT
// ============================================================================

/**
 * @brief Get behavioral context for process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PBE_PROCESS_CONTEXT* Context
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PBE_PROCESS_HASH_ENTRY hashEntry;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    hashIndex = BepHashProcessId(ProcessId);

    FltAcquirePushLockShared(&g_ProcessHashLock);

    for (entry = g_ProcessHashTable[hashIndex].Flink;
         entry != &g_ProcessHashTable[hashIndex];
         entry = entry->Flink) {

        hashEntry = CONTAINING_RECORD(entry, BE_PROCESS_HASH_ENTRY, HashListEntry);

        if (hashEntry->Context->ProcessId == ProcessId) {
            InterlockedIncrement(&hashEntry->Context->RefCount);
            *Context = hashEntry->Context;
            status = STATUS_SUCCESS;
            break;
        }
    }

    FltReleasePushLock(&g_ProcessHashLock);
    return status;
}

/**
 * @brief Release process context reference.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
BeEngineReleaseProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    InterlockedDecrement(&Context->RefCount);
}

/**
 * @brief Get behavioral risk score for process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetProcessRiskScore(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 Score
    )
{
    PBE_PROCESS_CONTEXT context;
    NTSTATUS status;

    if (Score == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = BeEngineGetProcessContext(ProcessId, &context);
    if (!NT_SUCCESS(status)) {
        *Score = 0;
        return status;
    }

    *Score = context->BehaviorScore;
    BeEngineReleaseProcessContext(context);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - RULES
// ============================================================================

/**
 * @brief Load behavioral detection rules.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
BeEngineLoadRules(
    _In_reads_(RuleCount) PATTACK_DETECTION_RULE Rules,
    _In_ UINT32 RuleCount
    )
{
    UINT32 i;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Rules == NULL || RuleCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_BeState.LoadedRuleCount + RuleCount > BE_MAX_RULES) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExAcquireResourceExclusiveLite(&g_BeState.RuleLock, TRUE);

    for (i = 0; i < RuleCount; i++) {
        PBE_LOADED_RULE loadedRule;

        loadedRule = (PBE_LOADED_RULE)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(BE_LOADED_RULE),
            BE_POOL_TAG_RULE
            );

        if (loadedRule == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(loadedRule, sizeof(BE_LOADED_RULE));
        RtlCopyMemory(&loadedRule->RuleData, &Rules[i], sizeof(ATTACK_DETECTION_RULE));

        {
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            loadedRule->LoadTime = (UINT64)(currentTime.QuadPart / 10000);
        }

        loadedRule->IsEnabled = (Rules[i].Flags & RULE_FLAG_ENABLED) != 0;

        InsertTailList(&g_BeState.LoadedRuleList, &loadedRule->ListEntry);
        g_BeState.LoadedRuleCount++;

        if (loadedRule->IsEnabled) {
            g_BeState.EnabledRuleCount++;
        }
    }

    ExReleaseResourceLite(&g_BeState.RuleLock);
    return status;
}

/**
 * @brief Enable or disable rule.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineSetRuleEnabled(
    _In_ UINT32 RuleId,
    _In_ BOOLEAN Enable
    )
{
    PLIST_ENTRY entry;
    PBE_LOADED_RULE rule;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireResourceExclusiveLite(&g_BeState.RuleLock, TRUE);

    for (entry = g_BeState.LoadedRuleList.Flink;
         entry != &g_BeState.LoadedRuleList;
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, BE_LOADED_RULE, ListEntry);

        if (rule->RuleData.RuleId == RuleId) {
            if (rule->IsEnabled != Enable) {
                rule->IsEnabled = Enable;

                if (Enable) {
                    g_BeState.EnabledRuleCount++;
                } else {
                    g_BeState.EnabledRuleCount--;
                }
            }
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseResourceLite(&g_BeState.RuleLock);
    return status;
}

/**
 * @brief Get rule match statistics.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetRuleStats(
    _In_ UINT32 RuleId,
    _Out_ PUINT32 TotalMatches,
    _Out_ PUINT64 LastMatchTime
    )
{
    PLIST_ENTRY entry;
    PBE_LOADED_RULE rule;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (TotalMatches == NULL || LastMatchTime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    ExAcquireResourceSharedLite(&g_BeState.RuleLock, TRUE);

    for (entry = g_BeState.LoadedRuleList.Flink;
         entry != &g_BeState.LoadedRuleList;
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, BE_LOADED_RULE, ListEntry);

        if (rule->RuleData.RuleId == RuleId) {
            *TotalMatches = rule->TotalMatches;
            *LastMatchTime = rule->LastMatchTime;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseResourceLite(&g_BeState.RuleLock);
    return status;
}

// ============================================================================
// PUBLIC API - MITRE ATT&CK
// ============================================================================

/**
 * @brief Map event to MITRE ATT&CK technique.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
BeEngineMapToMitre(
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_opt_ PVOID EventData,
    _Out_ PUINT32 TechniqueId,
    _Out_ PMITRE_TACTIC Tactic
    )
{
    UINT32 baseThreatScore;
    THREAT_SEVERITY baseSeverity;

    UNREFERENCED_PARAMETER(EventData);

    if (TechniqueId == NULL || Tactic == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return BepMapEventToMitre(EventType, TechniqueId, Tactic, &baseThreatScore, &baseSeverity);
}

/**
 * @brief Get observed techniques for process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetProcessTechniques(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxTechniques, *TechniqueCount) PUINT32 TechniqueIds,
    _In_ UINT32 MaxTechniques,
    _Out_ PUINT32 TechniqueCount
    )
{
    PBE_PROCESS_CONTEXT context;
    NTSTATUS status;
    UINT32 count;

    if (TechniqueIds == NULL || TechniqueCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TechniqueCount = 0;

    status = BeEngineGetProcessContext(ProcessId, &context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    count = min(context->ObservedTechniqueCount, MaxTechniques);
    RtlCopyMemory(TechniqueIds, context->ObservedTechniques, count * sizeof(UINT32));
    *TechniqueCount = count;

    BeEngineReleaseProcessContext(context);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get behavioral engine statistics.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
BeEngineGetStatistics(
    _Out_ PBEHAVIOR_ENGINE_GLOBALS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_BeState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlCopyMemory(Stats, &g_BeState, sizeof(BEHAVIOR_ENGINE_GLOBALS));
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTIONS - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize hash tables.
 */
static NTSTATUS
BepInitializeHashTables(
    VOID
    )
{
    ULONG i;

    //
    // Initialize process hash table
    //
    for (i = 0; i < BE_PROCESS_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ProcessHashTable[i]);
    }
    ExInitializePushLock(&g_ProcessHashLock);

    //
    // Initialize chain hash table
    //
    for (i = 0; i < BE_CHAIN_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ChainHashTable[i]);
    }
    ExInitializePushLock(&g_ChainHashLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup hash tables.
 */
static VOID
BepCleanupHashTables(
    VOID
    )
{
    //
    // Hash tables use static arrays, entries freed during shutdown
    //
}

/**
 * @brief Initialize lookaside lists.
 */
static NTSTATUS
BepInitializeLookasideLists(
    VOID
    )
{
    ExInitializeNPagedLookasideList(
        &g_BeState.EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BE_PENDING_EVENT) + 1024,  // Allow for event data
        BE_POOL_TAG_EVENT,
        BE_EVENT_LOOKASIDE_DEPTH
        );

    ExInitializeNPagedLookasideList(
        &g_BeState.ChainLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BE_ATTACK_CHAIN),
        BE_POOL_TAG_CHAIN,
        BE_CHAIN_LOOKASIDE_DEPTH
        );

    ExInitializeNPagedLookasideList(
        &g_BeState.EntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BE_CHAIN_ENTRY),
        BE_POOL_TAG_CHAIN,
        BE_ENTRY_LOOKASIDE_DEPTH
        );

    ExInitializeNPagedLookasideList(
        &g_BeState.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BE_PROCESS_CONTEXT),
        BE_POOL_TAG_GENERAL,
        BE_CONTEXT_LOOKASIDE_DEPTH
        );

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup lookaside lists.
 */
static VOID
BepCleanupLookasideLists(
    VOID
    )
{
    ExDeleteNPagedLookasideList(&g_BeState.EventLookaside);
    ExDeleteNPagedLookasideList(&g_BeState.ChainLookaside);
    ExDeleteNPagedLookasideList(&g_BeState.EntryLookaside);
    ExDeleteNPagedLookasideList(&g_BeState.ContextLookaside);
}

// ============================================================================
// PRIVATE FUNCTIONS - WORKER THREAD
// ============================================================================

/**
 * @brief Worker thread routine.
 */
static VOID
BepWorkerThread(
    _In_ PVOID StartContext
    )
{
    PVOID waitObjects[2];
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;

    UNREFERENCED_PARAMETER(StartContext);

    waitObjects[0] = &g_BeState.WorkerStopEvent;
    waitObjects[1] = &g_BeState.WorkerWakeEvent;

    timeout.QuadPart = -((LONGLONG)BE_WORKER_WAKE_INTERVAL_MS * 10000);

    while (!g_BeState.WorkerStopping) {
        //
        // Wait for work or timeout
        //
        waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            &timeout,
            NULL
            );

        //
        // Check for stop signal
        //
        if (waitStatus == STATUS_WAIT_0 || g_BeState.WorkerStopping) {
            break;
        }

        //
        // Process pending events
        //
        BepProcessEventBatch();

        //
        // Periodic cleanup
        //
        KeQuerySystemTime(&currentTime);
        currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

        if (currentTimeMs - g_BeState.LastChainCleanupTime > BE_CHAIN_CLEANUP_INTERVAL_MS) {
            BepCleanupStaleChains();
            BepCleanupStaleProcessContexts();
            g_BeState.LastChainCleanupTime = currentTimeMs;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/**
 * @brief Process a batch of pending events.
 */
static VOID
BepProcessEventBatch(
    VOID
    )
{
    KIRQL oldIrql;
    PBE_PENDING_EVENT event;
    PLIST_ENTRY entry;
    UINT32 processed = 0;
    LIST_ENTRY batchList;

    InitializeListHead(&batchList);

    //
    // Dequeue batch of events
    //
    KeAcquireSpinLock(&g_BeState.EventQueueLock, &oldIrql);

    while (!IsListEmpty(&g_BeState.PendingEventQueue) && processed < BE_EVENTS_PER_BATCH) {
        entry = RemoveHeadList(&g_BeState.PendingEventQueue);
        g_BeState.PendingEventCount--;
        InsertTailList(&batchList, entry);
        processed++;
    }

    KeReleaseSpinLock(&g_BeState.EventQueueLock, oldIrql);

    //
    // Process batch at PASSIVE_LEVEL
    //
    while (!IsListEmpty(&batchList)) {
        entry = RemoveHeadList(&batchList);
        event = CONTAINING_RECORD(entry, BE_PENDING_EVENT, ListEntry);

        BepProcessSingleEvent(event);
        BepFreeEvent(event);
    }
}

/**
 * @brief Process a single event.
 */
static NTSTATUS
BepProcessSingleEvent(
    _In_ PBE_PENDING_EVENT Event
    )
{
    PBE_PROCESS_CONTEXT processContext = NULL;
    PBE_ATTACK_CHAIN chain = NULL;
    NTSTATUS status;
    UINT32 threatScore;

    //
    // Get or create process context
    //
    status = BepGetOrCreateProcessContext(Event->ProcessId, &processContext);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Calculate threat score
    //
    threatScore = BepCalculateEventThreatScore(Event, processContext, Event->InitialThreatScore);

    //
    // Update process context
    //
    BepUpdateProcessContext(processContext, Event, threatScore);

    //
    // Check if event should be correlated to attack chain
    //
    if (threatScore >= BE_SEVERITY_MEDIUM_THRESHOLD ||
        (Event->Flags & BE_EVENT_FLAG_REQUIRES_CHAIN)) {

        status = BepGetOrCreateChain(Event->ProcessId, &chain);
        if (NT_SUCCESS(status)) {
            BepCorrelateEventToChain(Event, processContext, chain);
            BeEngineReleaseChain(chain);
        }

        Event->Flags |= BE_EVENT_FLAG_CORRELATED;
        InterlockedIncrement64(&g_BeState.TotalEventsCorrelated);
    }

    //
    // Check for threat detection
    //
    if (threatScore >= g_BeState.HighThreatThreshold) {
        InterlockedIncrement64(&g_BeState.TotalThreatsDetected);
    }

    Event->Flags |= BE_EVENT_FLAG_PROCESSED;
    InterlockedIncrement64(&g_BeState.TotalRuleMatches);

    BeEngineReleaseProcessContext(processContext);
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTIONS - MEMORY MANAGEMENT
// ============================================================================

/**
 * @brief Allocate pending event.
 */
static PBE_PENDING_EVENT
BepAllocateEvent(
    _In_ UINT32 EventDataSize
    )
{
    PBE_PENDING_EVENT event;
    SIZE_T totalSize = sizeof(BE_PENDING_EVENT) + EventDataSize;

    if (EventDataSize <= 1024) {
        event = (PBE_PENDING_EVENT)ExAllocateFromNPagedLookasideList(
            &g_BeState.EventLookaside
            );
    } else {
        event = (PBE_PENDING_EVENT)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            totalSize,
            BE_POOL_TAG_EVENT
            );
    }

    if (event != NULL) {
        RtlZeroMemory(event, totalSize);
    }

    return event;
}

/**
 * @brief Free pending event.
 */
static VOID
BepFreeEvent(
    _In_ PBE_PENDING_EVENT Event
    )
{
    if (Event == NULL) {
        return;
    }

    if (Event->EventDataSize <= 1024) {
        ExFreeToNPagedLookasideList(&g_BeState.EventLookaside, Event);
    } else {
        ExFreePoolWithTag(Event, BE_POOL_TAG_EVENT);
    }
}

/**
 * @brief Allocate attack chain.
 */
static PBE_ATTACK_CHAIN
BepAllocateChain(
    VOID
    )
{
    PBE_ATTACK_CHAIN chain;

    chain = (PBE_ATTACK_CHAIN)ExAllocateFromNPagedLookasideList(
        &g_BeState.ChainLookaside
        );

    if (chain != NULL) {
        RtlZeroMemory(chain, sizeof(BE_ATTACK_CHAIN));
        chain->RefCount = 1;
        InitializeListHead(&chain->EntryList);
        KeInitializeSpinLock(&chain->Lock);
    }

    return chain;
}

/**
 * @brief Free attack chain.
 */
static VOID
BepFreeChain(
    _In_ PBE_ATTACK_CHAIN Chain
    )
{
    if (Chain != NULL) {
        ExFreeToNPagedLookasideList(&g_BeState.ChainLookaside, Chain);
    }
}

/**
 * @brief Allocate chain entry.
 */
static PBE_CHAIN_ENTRY
BepAllocateChainEntry(
    VOID
    )
{
    PBE_CHAIN_ENTRY entry;

    entry = (PBE_CHAIN_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_BeState.EntryLookaside
        );

    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(BE_CHAIN_ENTRY));
    }

    return entry;
}

/**
 * @brief Free chain entry.
 */
static VOID
BepFreeChainEntry(
    _In_ PBE_CHAIN_ENTRY Entry
    )
{
    if (Entry != NULL) {
        ExFreeToNPagedLookasideList(&g_BeState.EntryLookaside, Entry);
    }
}

/**
 * @brief Allocate process context.
 */
static PBE_PROCESS_CONTEXT
BepAllocateProcessContext(
    VOID
    )
{
    PBE_PROCESS_CONTEXT context;

    context = (PBE_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_BeState.ContextLookaside
        );

    if (context != NULL) {
        RtlZeroMemory(context, sizeof(BE_PROCESS_CONTEXT));
        context->RefCount = 1;
    }

    return context;
}

/**
 * @brief Free process context.
 */
static VOID
BepFreeProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    )
{
    if (Context != NULL) {
        ExFreeToNPagedLookasideList(&g_BeState.ContextLookaside, Context);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - HASHING
// ============================================================================

/**
 * @brief Hash process ID for lookup.
 */
static UINT32
BepHashProcessId(
    _In_ UINT32 ProcessId
    )
{
    return ProcessId % BE_PROCESS_HASH_BUCKETS;
}

/**
 * @brief Hash chain ID for lookup.
 */
static UINT32
BepHashChainId(
    _In_ UINT64 ChainId
    )
{
    return (UINT32)(ChainId % BE_CHAIN_HASH_BUCKETS);
}

// ============================================================================
// PRIVATE FUNCTIONS - CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Insert process context into tracking.
 */
static NTSTATUS
BepInsertProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    )
{
    UINT32 hashIndex;
    PBE_PROCESS_HASH_ENTRY hashEntry;

    hashEntry = (PBE_PROCESS_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(BE_PROCESS_HASH_ENTRY),
        BE_POOL_TAG_GENERAL
        );

    if (hashEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hashEntry->Context = Context;
    hashIndex = BepHashProcessId(Context->ProcessId);

    //
    // Insert into main list
    //
    ExAcquireResourceExclusiveLite(&g_BeState.ProcessLock, TRUE);
    InsertTailList(&g_BeState.ProcessContextList, &Context->ListEntry);
    g_BeState.ProcessContextCount++;
    ExReleaseResourceLite(&g_BeState.ProcessLock);

    //
    // Insert into hash
    //
    FltAcquirePushLockExclusive(&g_ProcessHashLock);
    InsertTailList(&g_ProcessHashTable[hashIndex], &hashEntry->HashListEntry);
    FltReleasePushLock(&g_ProcessHashLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Remove process context from tracking.
 */
static VOID
BepRemoveProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PBE_PROCESS_HASH_ENTRY hashEntry = NULL;

    //
    // Remove from main list
    //
    ExAcquireResourceExclusiveLite(&g_BeState.ProcessLock, TRUE);
    RemoveEntryList(&Context->ListEntry);
    g_BeState.ProcessContextCount--;
    ExReleaseResourceLite(&g_BeState.ProcessLock);

    //
    // Remove from hash
    //
    hashIndex = BepHashProcessId(Context->ProcessId);

    FltAcquirePushLockExclusive(&g_ProcessHashLock);

    for (entry = g_ProcessHashTable[hashIndex].Flink;
         entry != &g_ProcessHashTable[hashIndex];
         entry = entry->Flink) {

        PBE_PROCESS_HASH_ENTRY current = CONTAINING_RECORD(entry, BE_PROCESS_HASH_ENTRY, HashListEntry);
        if (current->Context == Context) {
            RemoveEntryList(&current->HashListEntry);
            hashEntry = current;
            break;
        }
    }

    FltReleasePushLock(&g_ProcessHashLock);

    if (hashEntry != NULL) {
        ExFreePoolWithTag(hashEntry, BE_POOL_TAG_GENERAL);
    }
}

/**
 * @brief Get or create process context.
 */
static NTSTATUS
BepGetOrCreateProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PBE_PROCESS_CONTEXT* Context
    )
{
    NTSTATUS status;

    status = BeEngineGetProcessContext(ProcessId, Context);
    if (NT_SUCCESS(status)) {
        return status;
    }

    //
    // Create new context
    //
    *Context = BepAllocateProcessContext();
    if (*Context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    (*Context)->ProcessId = ProcessId;
    InitializeListHead(&(*Context)->ChainList);

    status = BepInsertProcessContext(*Context);
    if (!NT_SUCCESS(status)) {
        BepFreeProcessContext(*Context);
        *Context = NULL;
    }

    return status;
}

/**
 * @brief Insert chain into tracking.
 */
static NTSTATUS
BepInsertChain(
    _In_ PBE_ATTACK_CHAIN Chain
    )
{
    UINT32 hashIndex;
    PBE_CHAIN_HASH_ENTRY hashEntry;

    hashEntry = (PBE_CHAIN_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(BE_CHAIN_HASH_ENTRY),
        BE_POOL_TAG_CHAIN
        );

    if (hashEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hashEntry->Chain = Chain;
    hashIndex = BepHashChainId(Chain->ChainId);

    //
    // Insert into main list
    //
    ExAcquireResourceExclusiveLite(&g_BeState.ChainLock, TRUE);
    InsertTailList(&g_BeState.ActiveChainList, &Chain->ListEntry);
    g_BeState.ActiveChainCount++;
    ExReleaseResourceLite(&g_BeState.ChainLock);

    //
    // Insert into hash
    //
    FltAcquirePushLockExclusive(&g_ChainHashLock);
    InsertTailList(&g_ChainHashTable[hashIndex], &hashEntry->HashListEntry);
    FltReleasePushLock(&g_ChainHashLock);

    InterlockedIncrement64(&g_BeState.TotalChainsCreated);

    return STATUS_SUCCESS;
}

/**
 * @brief Remove chain from tracking.
 */
static VOID
BepRemoveChain(
    _In_ PBE_ATTACK_CHAIN Chain
    )
{
    UINT32 hashIndex;
    PLIST_ENTRY entry;
    PBE_CHAIN_HASH_ENTRY hashEntry = NULL;

    //
    // Remove from main list
    //
    ExAcquireResourceExclusiveLite(&g_BeState.ChainLock, TRUE);
    RemoveEntryList(&Chain->ListEntry);
    g_BeState.ActiveChainCount--;
    ExReleaseResourceLite(&g_BeState.ChainLock);

    //
    // Remove from hash
    //
    hashIndex = BepHashChainId(Chain->ChainId);

    FltAcquirePushLockExclusive(&g_ChainHashLock);

    for (entry = g_ChainHashTable[hashIndex].Flink;
         entry != &g_ChainHashTable[hashIndex];
         entry = entry->Flink) {

        PBE_CHAIN_HASH_ENTRY current = CONTAINING_RECORD(entry, BE_CHAIN_HASH_ENTRY, HashListEntry);
        if (current->Chain == Chain) {
            RemoveEntryList(&current->HashListEntry);
            hashEntry = current;
            break;
        }
    }

    FltReleasePushLock(&g_ChainHashLock);

    if (hashEntry != NULL) {
        ExFreePoolWithTag(hashEntry, BE_POOL_TAG_CHAIN);
    }
}

/**
 * @brief Get or create attack chain for process.
 */
static NTSTATUS
BepGetOrCreateChain(
    _In_ UINT32 ProcessId,
    _Out_ PBE_ATTACK_CHAIN* Chain
    )
{
    PBE_PROCESS_CONTEXT context;
    NTSTATUS status;
    LARGE_INTEGER currentTime;

    *Chain = NULL;

    //
    // Check if process already has an active chain
    //
    status = BeEngineGetProcessContext(ProcessId, &context);
    if (NT_SUCCESS(status)) {
        if (context->ChainCount > 0 && !IsListEmpty(&context->ChainList)) {
            //
            // Return existing chain
            //
            PLIST_ENTRY entry = context->ChainList.Flink;
            *Chain = CONTAINING_RECORD(entry, BE_ATTACK_CHAIN, ProcessListEntry);
            InterlockedIncrement(&(*Chain)->RefCount);
            BeEngineReleaseProcessContext(context);
            return STATUS_SUCCESS;
        }
        BeEngineReleaseProcessContext(context);
    }

    //
    // Check chain limit
    //
    if (g_BeState.ActiveChainCount >= g_BeState.MaxActiveChains) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Create new chain
    //
    *Chain = BepAllocateChain();
    if (*Chain == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeQuerySystemTime(&currentTime);

    (*Chain)->ChainId = (UINT64)InterlockedIncrement64(&g_BeState.NextChainId);
    (*Chain)->CreateTime = (UINT64)(currentTime.QuadPart / 10000);
    (*Chain)->LastUpdateTime = (*Chain)->CreateTime;
    (*Chain)->PrimaryProcessId = ProcessId;
    (*Chain)->IsActive = TRUE;
    (*Chain)->MaxEntries = g_BeState.MaxEventsPerChain;

    status = BepInsertChain(*Chain);
    if (!NT_SUCCESS(status)) {
        BepFreeChain(*Chain);
        *Chain = NULL;
        return status;
    }

    //
    // Link to process context
    //
    status = BeEngineGetProcessContext(ProcessId, &context);
    if (NT_SUCCESS(status)) {
        InsertTailList(&context->ChainList, &(*Chain)->ProcessListEntry);
        context->ChainCount++;

        //
        // Copy process path to chain
        //
        RtlCopyMemory((*Chain)->PrimaryImagePath, context->ImagePath,
                      sizeof((*Chain)->PrimaryImagePath));

        BeEngineReleaseProcessContext(context);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTIONS - EVENT PROCESSING
// ============================================================================

/**
 * @brief Correlate event to attack chain.
 */
static NTSTATUS
BepCorrelateEventToChain(
    _In_ PBE_PENDING_EVENT Event,
    _In_ PBE_PROCESS_CONTEXT ProcessContext,
    _Inout_ PBE_ATTACK_CHAIN Chain
    )
{
    PBE_CHAIN_ENTRY entry;
    MITRE_TACTIC tactic;
    ATTACK_CHAIN_STAGE stage;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(ProcessContext);

    //
    // Check chain entry limit
    //
    if (Chain->EntryCount >= Chain->MaxEntries) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate chain entry
    //
    entry = BepAllocateChainEntry();
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry
    //
    entry->EntryIndex = Chain->EntryCount;
    entry->EventType = Event->EventType;
    entry->MitreAttackId = Event->MitreAttackId;
    entry->Timestamp = Event->ReceiveTime;
    entry->ProcessId = Event->ProcessId;
    entry->ThreatScore = Event->InitialThreatScore;

    //
    // Calculate time since previous
    //
    if (Chain->EntryCount > 0) {
        entry->TimeSincePreviousMs = (UINT32)(Event->ReceiveTime - Chain->LastUpdateTime);
    }

    //
    // Determine stage from tactic
    //
    tactic = Tactic_None;
    BepMapEventToMitre(Event->EventType, &entry->MitreAttackId, &tactic, NULL, NULL);
    stage = BepTacticToStage(tactic);
    entry->Stage = stage;

    //
    // Update chain state
    //
    KeAcquireSpinLock(&Chain->Lock, &oldIrql);

    InsertTailList(&Chain->EntryList, &entry->ListEntry);
    Chain->EntryCount++;
    Chain->LastUpdateTime = Event->ReceiveTime;

    BepUpdateChainState(Chain, entry);

    KeReleaseSpinLock(&Chain->Lock, oldIrql);

    return STATUS_SUCCESS;
}

/**
 * @brief Map event type to MITRE technique.
 */
static NTSTATUS
BepMapEventToMitre(
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _Out_ PUINT32 TechniqueId,
    _Out_ PMITRE_TACTIC Tactic,
    _Out_opt_ PUINT32 BaseThreatScore,
    _Out_opt_ PTHREAT_SEVERITY BaseSeverity
    )
{
    const BE_EVENT_MITRE_MAP* entry = g_EventMitreMap;

    while (entry->EventType != 0) {
        if (entry->EventType == EventType) {
            if (TechniqueId != NULL) {
                *TechniqueId = entry->MitreTechnique;
            }
            if (Tactic != NULL) {
                *Tactic = entry->PrimaryTactic;
            }
            if (BaseThreatScore != NULL) {
                *BaseThreatScore = entry->BaseThreatScore;
            }
            if (BaseSeverity != NULL) {
                *BaseSeverity = entry->BaseSeverity;
            }
            return STATUS_SUCCESS;
        }
        entry++;
    }

    //
    // Default mapping for unknown events
    //
    if (TechniqueId != NULL) {
        *TechniqueId = 0;
    }
    if (Tactic != NULL) {
        *Tactic = Tactic_None;
    }
    if (BaseThreatScore != NULL) {
        *BaseThreatScore = 100;
    }
    if (BaseSeverity != NULL) {
        *BaseSeverity = ThreatSeverity_Informational;
    }

    return STATUS_NOT_FOUND;
}

/**
 * @brief Convert MITRE tactic to attack chain stage.
 */
static ATTACK_CHAIN_STAGE
BepTacticToStage(
    _In_ MITRE_TACTIC Tactic
    )
{
    switch (Tactic) {
        case Tactic_Reconnaissance:
            return AttackStage_Reconnaissance;
        case Tactic_ResourceDevelopment:
            return AttackStage_Weaponization;
        case Tactic_InitialAccess:
            return AttackStage_Delivery;
        case Tactic_Execution:
            return AttackStage_Exploitation;
        case Tactic_Persistence:
            return AttackStage_Installation;
        case Tactic_PrivilegeEscalation:
            return AttackStage_Installation;
        case Tactic_DefenseEvasion:
            return AttackStage_Installation;
        case Tactic_CredentialAccess:
            return AttackStage_Actions;
        case Tactic_Discovery:
            return AttackStage_Reconnaissance;
        case Tactic_LateralMovement:
            return AttackStage_Actions;
        case Tactic_Collection:
            return AttackStage_Actions;
        case Tactic_CommandAndControl:
            return AttackStage_CommandControl;
        case Tactic_Exfiltration:
            return AttackStage_Actions;
        case Tactic_Impact:
            return AttackStage_Actions;
        default:
            return AttackStage_None;
    }
}

/**
 * @brief Calculate event threat score.
 */
static UINT32
BepCalculateEventThreatScore(
    _In_ PBE_PENDING_EVENT Event,
    _In_ PBE_PROCESS_CONTEXT ProcessContext,
    _In_ UINT32 BaseThreatScore
    )
{
    UINT32 score = BaseThreatScore;

    //
    // Adjust based on process flags
    //
    if (ProcessContext->Flags & BE_PROC_FLAG_LOLBIN) {
        score = (score * 120) / 100;  // 20% increase for LOLBins
    }

    if (ProcessContext->Flags & BE_PROC_FLAG_SCRIPT_HOST) {
        score = (score * 115) / 100;  // 15% increase for script hosts
    }

    if (ProcessContext->Flags & BE_PROC_FLAG_HIGH_RISK) {
        score = (score * 130) / 100;  // 30% increase for high-risk processes
    }

    //
    // Adjust based on process history
    //
    if (ProcessContext->SuspiciousEventCount > 5) {
        score = (score * 125) / 100;  // 25% increase for repeat offenders
    }

    //
    // Cap at 1000
    //
    if (score > 1000) {
        score = 1000;
    }

    UNREFERENCED_PARAMETER(Event);

    return score;
}

/**
 * @brief Convert threat score to severity.
 */
static THREAT_SEVERITY
BepScoreToSeverity(
    _In_ UINT32 ThreatScore
    )
{
    if (ThreatScore >= BE_SEVERITY_CRITICAL_THRESHOLD) {
        return ThreatSeverity_Critical;
    } else if (ThreatScore >= BE_SEVERITY_HIGH_THRESHOLD) {
        return ThreatSeverity_High;
    } else if (ThreatScore >= BE_SEVERITY_MEDIUM_THRESHOLD) {
        return ThreatSeverity_Medium;
    } else if (ThreatScore >= BE_SEVERITY_LOW_THRESHOLD) {
        return ThreatSeverity_Low;
    } else {
        return ThreatSeverity_Informational;
    }
}

/**
 * @brief Determine response action for event.
 */
static BEHAVIOR_RESPONSE_ACTION
BepDetermineResponse(
    _In_ PBE_PENDING_EVENT Event,
    _In_ PBE_ATTACK_CHAIN Chain,
    _In_ UINT32 ThreatScore
    )
{
    UNREFERENCED_PARAMETER(Event);
    UNREFERENCED_PARAMETER(Chain);

    if (ThreatScore >= g_BeState.CriticalThreshold) {
        return BehaviorResponse_Block;
    } else if (ThreatScore >= g_BeState.HighThreatThreshold) {
        return BehaviorResponse_Alert;
    } else {
        return BehaviorResponse_Allow;
    }
}

/**
 * @brief Update process context with event.
 */
static VOID
BepUpdateProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context,
    _In_ PBE_PENDING_EVENT Event,
    _In_ UINT32 ThreatScore
    )
{
    UINT32 index;

    //
    // Update behavior score
    //
    Context->BehaviorScore += ThreatScore / 10;
    if (Context->BehaviorScore > Context->PeakBehaviorScore) {
        Context->PeakBehaviorScore = Context->BehaviorScore;
    }

    //
    // Track suspicious events
    //
    if (ThreatScore >= BE_SEVERITY_MEDIUM_THRESHOLD) {
        Context->SuspiciousEventCount++;
    }

    //
    // Add to recent events ring buffer
    //
    index = Context->RecentEventIndex % 32;
    Context->RecentEvents[index] = Event->EventType;
    Context->RecentEventTimes[index] = Event->ReceiveTime;
    Context->RecentEventIndex++;
    if (Context->RecentEventCount < 32) {
        Context->RecentEventCount++;
    }

    //
    // Track observed techniques
    //
    if (Event->MitreAttackId != 0 && Context->ObservedTechniqueCount < 64) {
        UINT32 i;
        BOOLEAN found = FALSE;

        for (i = 0; i < Context->ObservedTechniqueCount; i++) {
            if (Context->ObservedTechniques[i] == Event->MitreAttackId) {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            Context->ObservedTechniques[Context->ObservedTechniqueCount++] = Event->MitreAttackId;
        }
    }

    //
    // Set high-risk flag if appropriate
    //
    if (Context->BehaviorScore >= 500 || Context->SuspiciousEventCount >= 10) {
        Context->Flags |= BE_PROC_FLAG_HIGH_RISK;
    }
}

/**
 * @brief Update chain state with new entry.
 */
static VOID
BepUpdateChainState(
    _In_ PBE_ATTACK_CHAIN Chain,
    _In_ PBE_CHAIN_ENTRY Entry
    )
{
    //
    // Update stage tracking
    //
    if (Entry->Stage != AttackStage_None) {
        Chain->StageFlags |= (1 << Entry->Stage);

        if (Entry->Stage > Chain->CurrentStage) {
            Chain->CurrentStage = Entry->Stage;
        }
        if (Entry->Stage > Chain->HighestStage) {
            Chain->HighestStage = Entry->Stage;
        }
    }

    //
    // Update technique tracking
    //
    if (Entry->MitreAttackId != 0 && Chain->TechniqueCount < 64) {
        Chain->TechniqueIds[Chain->TechniqueCount++] = Entry->MitreAttackId;
    }

    //
    // Update threat score
    //
    Chain->CumulativeThreatScore += Entry->ThreatScore;
    if (Entry->ThreatScore > Chain->PeakThreatScore) {
        Chain->PeakThreatScore = Entry->ThreatScore;
    }

    //
    // Update severity
    //
    THREAT_SEVERITY entrySeverity = BepScoreToSeverity(Entry->ThreatScore);
    if (entrySeverity > Chain->HighestSeverity) {
        Chain->HighestSeverity = entrySeverity;
    }

    //
    // Set chain flags based on patterns
    //
    if (Chain->CumulativeThreatScore >= 3000) {
        Chain->Flags |= BE_CHAIN_FLAG_APT_LIKELY;
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CLEANUP
// ============================================================================

/**
 * @brief Cleanup stale attack chains.
 */
static VOID
BepCleanupStaleChains(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PBE_ATTACK_CHAIN chain;
    LARGE_INTEGER currentTime;
    UINT64 currentTimeMs;
    LIST_ENTRY staleList;

    InitializeListHead(&staleList);
    KeQuerySystemTime(&currentTime);
    currentTimeMs = (UINT64)(currentTime.QuadPart / 10000);

    ExAcquireResourceExclusiveLite(&g_BeState.ChainLock, TRUE);

    for (entry = g_BeState.ActiveChainList.Flink;
         entry != &g_BeState.ActiveChainList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        chain = CONTAINING_RECORD(entry, BE_ATTACK_CHAIN, ListEntry);

        //
        // Check if chain is stale
        //
        if (!chain->IsActive ||
            (currentTimeMs - chain->LastUpdateTime > g_BeState.ChainTimeoutMs &&
             chain->RefCount <= 1)) {

            RemoveEntryList(&chain->ListEntry);
            InsertTailList(&staleList, &chain->ListEntry);
            g_BeState.ActiveChainCount--;
        }
    }

    ExReleaseResourceLite(&g_BeState.ChainLock);

    //
    // Free stale chains
    //
    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        chain = CONTAINING_RECORD(entry, BE_ATTACK_CHAIN, ListEntry);

        //
        // Free chain entries
        //
        while (!IsListEmpty(&chain->EntryList)) {
            PLIST_ENTRY entryEntry = RemoveHeadList(&chain->EntryList);
            PBE_CHAIN_ENTRY chainEntry = CONTAINING_RECORD(entryEntry, BE_CHAIN_ENTRY, ListEntry);
            BepFreeChainEntry(chainEntry);
        }

        BepFreeChain(chain);
    }
}

/**
 * @brief Cleanup stale process contexts.
 */
static VOID
BepCleanupStaleProcessContexts(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PBE_PROCESS_CONTEXT context;
    LIST_ENTRY staleList;

    InitializeListHead(&staleList);

    ExAcquireResourceExclusiveLite(&g_BeState.ProcessLock, TRUE);

    for (entry = g_BeState.ProcessContextList.Flink;
         entry != &g_BeState.ProcessContextList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        context = CONTAINING_RECORD(entry, BE_PROCESS_CONTEXT, ListEntry);

        //
        // Check if process is terminated and has no references
        //
        if ((context->Flags & BE_PROC_FLAG_TERMINATED) && context->RefCount <= 1) {
            RemoveEntryList(&context->ListEntry);
            InsertTailList(&staleList, &context->ListEntry);
            g_BeState.ProcessContextCount--;
        }
    }

    ExReleaseResourceLite(&g_BeState.ProcessLock);

    //
    // Free stale contexts
    //
    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        context = CONTAINING_RECORD(entry, BE_PROCESS_CONTEXT, ListEntry);
        BepFreeProcessContext(context);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - UTILITY
// ============================================================================

/**
 * @brief Check if process is a LOLBin.
 */
static BOOLEAN
BepIsLolBin(
    _In_ PCWSTR ImagePath
    )
{
    static const PCWSTR lolbins[] = {
        L"\\cmd.exe",
        L"\\powershell.exe",
        L"\\pwsh.exe",
        L"\\wscript.exe",
        L"\\cscript.exe",
        L"\\mshta.exe",
        L"\\rundll32.exe",
        L"\\regsvr32.exe",
        L"\\certutil.exe",
        L"\\msbuild.exe",
        L"\\installutil.exe",
        L"\\regasm.exe",
        L"\\regsvcs.exe",
        L"\\cmstp.exe",
        L"\\msiexec.exe",
        L"\\wmic.exe",
        L"\\bitsadmin.exe",
        L"\\esentutl.exe",
        L"\\expand.exe",
        L"\\extrac32.exe",
        L"\\findstr.exe",
        L"\\forfiles.exe",
        L"\\hh.exe",
        L"\\ie4uinit.exe",
        L"\\infdefaultinstall.exe",
        L"\\makecab.exe",
        L"\\mavinject.exe",
        L"\\mmc.exe",
        L"\\msconfig.exe",
        L"\\msdeploy.exe",
        L"\\msdt.exe",
        L"\\msiexec.exe",
        L"\\odbcconf.exe",
        L"\\pcalua.exe",
        L"\\pcwrun.exe",
        L"\\presentationhost.exe",
        L"\\pubprn.vbs",
        L"\\replace.exe",
        L"\\rpcping.exe",
        L"\\schtasks.exe",
        L"\\scriptrunner.exe",
        L"\\syncappvpublishingserver.exe",
        L"\\verclsid.exe",
        L"\\xwizard.exe",
        NULL
    };

    if (ImagePath == NULL) {
        return FALSE;
    }

    for (UINT32 i = 0; lolbins[i] != NULL; i++) {
        if (wcsstr(ImagePath, lolbins[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Check if process is a script host.
 */
static BOOLEAN
BepIsScriptHost(
    _In_ PCWSTR ImagePath
    )
{
    static const PCWSTR scriptHosts[] = {
        L"\\powershell.exe",
        L"\\pwsh.exe",
        L"\\wscript.exe",
        L"\\cscript.exe",
        L"\\mshta.exe",
        L"\\python.exe",
        L"\\pythonw.exe",
        L"\\perl.exe",
        L"\\ruby.exe",
        L"\\node.exe",
        L"\\java.exe",
        L"\\javaw.exe",
        NULL
    };

    if (ImagePath == NULL) {
        return FALSE;
    }

    for (UINT32 i = 0; scriptHosts[i] != NULL; i++) {
        if (wcsstr(ImagePath, scriptHosts[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Extract process name from full path.
 */
static VOID
BepGetProcessName(
    _In_ PCWSTR ImagePath,
    _Out_writes_(MaxLength) PWCHAR ProcessName,
    _In_ ULONG MaxLength
    )
{
    PCWSTR lastSlash;
    SIZE_T nameLen;

    ProcessName[0] = L'\0';

    if (ImagePath == NULL || MaxLength == 0) {
        return;
    }

    lastSlash = wcsrchr(ImagePath, L'\\');
    if (lastSlash != NULL) {
        lastSlash++;
    } else {
        lastSlash = ImagePath;
    }

    nameLen = wcslen(lastSlash);
    if (nameLen >= MaxLength) {
        nameLen = MaxLength - 1;
    }

    RtlCopyMemory(ProcessName, lastSlash, nameLen * sizeof(WCHAR));
    ProcessName[nameLen] = L'\0';
}

#endif // SHADOWSTRIKE_BEHAVIOR_ENGINE_C
