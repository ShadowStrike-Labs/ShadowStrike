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
 * ShadowStrike NGAV - BEHAVIORAL ENGINE
 * ============================================================================
 *
 * @file BehaviorEngine.h
 * @brief Behavioral analysis engine header for ShadowSensor kernel driver.
 *
 * This module provides the core behavioral detection engine including:
 * - Event correlation and attack chain tracking
 * - MITRE ATT&CK technique detection
 * - Threat scoring and risk assessment
 * - Rule-based behavioral detection
 * - Anomaly detection
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <fltKernel.h>
#include "../../Shared/BehaviorTypes.h"
#include "../../Shared/AttackPatterns.h"

// ============================================================================
// BEHAVIORAL ENGINE CONFIGURATION
// ============================================================================

/**
 * @brief Pool tags.
 */
#define BE_POOL_TAG_GENERAL     'eBsS'
#define BE_POOL_TAG_EVENT       'vEsS'
#define BE_POOL_TAG_CHAIN       'cBsS'
#define BE_POOL_TAG_RULE        'rBsS'

/**
 * @brief Default configuration values.
 */
#define BE_DEFAULT_CHAIN_TIMEOUT_MS         300000      // 5 minutes
#define BE_DEFAULT_MAX_ACTIVE_CHAINS        10000
#define BE_DEFAULT_MAX_EVENTS_PER_CHAIN     1000
#define BE_DEFAULT_CORRELATION_WINDOW_MS    60000       // 1 minute
#define BE_DEFAULT_HIGH_THREAT_THRESHOLD    700         // 0-1000
#define BE_DEFAULT_CRITICAL_THRESHOLD       900         // 0-1000

/**
 * @brief Maximum limits.
 */
#define BE_MAX_RULES                        10000
#define BE_MAX_CHAIN_ENTRIES                256
#define BE_MAX_PENDING_EVENTS               100000

// ============================================================================
// EVENT PROCESSING
// ============================================================================

/**
 * @brief Pending behavioral event.
 */
typedef struct _BE_PENDING_EVENT {
    LIST_ENTRY ListEntry;
    
    // Event identification
    BEHAVIOR_CORRELATION_ID CorrelationId;
    BEHAVIOR_EVENT_TYPE EventType;
    BEHAVIOR_EVENT_CATEGORY Category;
    UINT64 ReceiveTime;
    
    // Event data (union of all event types)
    UINT32 EventDataSize;
    UINT32 Flags;
    
    // Pre-computed analysis
    UINT32 InitialThreatScore;
    THREAT_SEVERITY InitialSeverity;
    UINT32 MitreAttackId;                 // If directly mapped
    
    // Process context
    UINT32 ProcessId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    UINT32 Reserved;
    
    // Variable-length event data follows
    UINT8 EventData[ANYSIZE_ARRAY];
} BE_PENDING_EVENT, *PBE_PENDING_EVENT;

// Event flags
#define BE_EVENT_FLAG_HIGH_PRIORITY       0x00000001
#define BE_EVENT_FLAG_REQUIRES_CHAIN      0x00000002
#define BE_EVENT_FLAG_BLOCKING            0x00000004
#define BE_EVENT_FLAG_PROCESSED           0x00000008
#define BE_EVENT_FLAG_CORRELATED          0x00000010

// ============================================================================
// ATTACK CHAIN TRACKING
// ============================================================================

/**
 * @brief Attack chain entry.
 */
typedef struct _BE_CHAIN_ENTRY {
    LIST_ENTRY ListEntry;
    
    // Entry info
    UINT32 EntryIndex;
    BEHAVIOR_EVENT_TYPE EventType;
    ATTACK_CHAIN_STAGE Stage;
    UINT32 MitreAttackId;
    
    // Timing
    UINT64 Timestamp;
    UINT32 TimeSincePreviousMs;
    UINT32 Reserved;
    
    // Process info
    UINT32 ProcessId;
    UINT32 ThreadId;
    
    // Scoring
    UINT32 ThreatScore;
    UINT32 Confidence;
    
    // Brief description
    WCHAR Description[256];
} BE_CHAIN_ENTRY, *PBE_CHAIN_ENTRY;

/**
 * @brief Active attack chain.
 */
typedef struct _BE_ATTACK_CHAIN {
    LIST_ENTRY ListEntry;
    LIST_ENTRY ProcessListEntry;          // Per-process chain list
    
    // Chain identification
    UINT64 ChainId;
    UINT64 CreateTime;
    UINT64 LastUpdateTime;
    
    // Primary actor
    UINT32 PrimaryProcessId;
    UINT64 PrimaryProcessCreateTime;
    WCHAR PrimaryImagePath[MAX_FILE_PATH_LENGTH];
    
    // Chain state
    ATTACK_CHAIN_STAGE CurrentStage;
    ATTACK_CHAIN_STAGE HighestStage;
    UINT32 StageFlags;                    // Bitmask of observed stages
    UINT32 TacticFlags;                   // Bitmask of observed tactics
    
    // Techniques
    UINT32 TechniqueIds[64];
    UINT32 TechniqueCount;
    
    // Events
    LIST_ENTRY EntryList;
    UINT32 EntryCount;
    UINT32 MaxEntries;
    
    // Scoring
    UINT32 CumulativeThreatScore;         // 0-10000
    UINT32 PeakThreatScore;
    THREAT_SEVERITY HighestSeverity;
    UINT32 Confidence;
    
    // Status
    UINT32 Flags;
    BOOLEAN IsActive;
    BOOLEAN IsBlocked;
    BOOLEAN IsRemediated;
    UINT8 Reserved;
    
    // Related processes
    UINT32 RelatedProcessIds[32];
    UINT32 RelatedProcessCount;
    
    // Lock
    KSPIN_LOCK Lock;
    
    // Reference counting
    volatile LONG RefCount;
} BE_ATTACK_CHAIN, *PBE_ATTACK_CHAIN;

// Chain flags
#define BE_CHAIN_FLAG_APT_LIKELY          0x00000001
#define BE_CHAIN_FLAG_RANSOMWARE          0x00000002
#define BE_CHAIN_FLAG_COINMINER           0x00000004
#define BE_CHAIN_FLAG_CREDENTIAL_THEFT    0x00000008
#define BE_CHAIN_FLAG_DATA_EXFIL          0x00000010
#define BE_CHAIN_FLAG_LATERAL_MOVEMENT    0x00000020
#define BE_CHAIN_FLAG_USER_NOTIFIED       0x00000040
#define BE_CHAIN_FLAG_AUTO_REMEDIATE      0x00000080
#define BE_CHAIN_FLAG_FALSE_POSITIVE      0x00000100
#define BE_CHAIN_FLAG_PENDING_REVIEW      0x00000200
#define BE_CHAIN_FLAG_ESCALATED           0x00000400

// ============================================================================
// PROCESS BEHAVIORAL CONTEXT
// ============================================================================

/**
 * @brief Per-process behavioral context.
 */
typedef struct _BE_PROCESS_CONTEXT {
    LIST_ENTRY ListEntry;
    
    // Process identification
    UINT32 ProcessId;
    UINT32 ParentProcessId;
    UINT64 ProcessCreateTime;
    PEPROCESS ProcessObject;
    
    // Process info
    WCHAR ImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
    UINT32 SessionId;
    UINT32 Flags;
    
    // Behavioral state
    UINT32 BehaviorScore;                 // Current behavioral risk score
    UINT32 PeakBehaviorScore;
    UINT32 SuspiciousEventCount;
    UINT32 BlockedEventCount;
    
    // Event history (recent events)
    BEHAVIOR_EVENT_TYPE RecentEvents[32];
    UINT64 RecentEventTimes[32];
    UINT32 RecentEventIndex;
    UINT32 RecentEventCount;
    
    // MITRE techniques observed
    UINT32 ObservedTechniques[64];
    UINT32 ObservedTechniqueCount;
    
    // Attack chains this process is involved in
    LIST_ENTRY ChainList;
    UINT32 ChainCount;
    
    // Anomaly detection baseline
    UINT32 BaselineChildProcessRate;      // Per hour
    UINT32 BaselineNetworkConnRate;       // Per hour
    UINT32 BaselineFileAccessRate;        // Per hour
    UINT32 BaselineRegistryAccessRate;    // Per hour
    BOOLEAN BaselineEstablished;
    UINT8 Reserved[3];
    
    // Reference counting
    volatile LONG RefCount;
} BE_PROCESS_CONTEXT, *PBE_PROCESS_CONTEXT;

// Process flags
#define BE_PROC_FLAG_SYSTEM               0x00000001
#define BE_PROC_FLAG_ELEVATED             0x00000002
#define BE_PROC_FLAG_SERVICE              0x00000004
#define BE_PROC_FLAG_NETWORK_SERVICE      0x00000008
#define BE_PROC_FLAG_MICROSOFT_SIGNED     0x00000010
#define BE_PROC_FLAG_HIGH_RISK            0x00000020
#define BE_PROC_FLAG_BLOCKED              0x00000040
#define BE_PROC_FLAG_TERMINATED           0x00000080
#define BE_PROC_FLAG_LOLBIN               0x00000100
#define BE_PROC_FLAG_SCRIPT_HOST          0x00000200

// ============================================================================
// BEHAVIORAL RULES
// ============================================================================

/**
 * @brief Loaded behavioral rule.
 */
typedef struct _BE_LOADED_RULE {
    LIST_ENTRY ListEntry;
    
    // Rule metadata
    ATTACK_DETECTION_RULE RuleData;
    
    // Runtime state
    UINT64 LoadTime;
    UINT64 LastMatchTime;
    UINT32 TotalMatches;
    UINT32 FalsePositives;                // Reported FPs
    
    // Compiled conditions (for fast matching)
    PVOID CompiledConditions;
    UINT32 CompiledConditionsSize;
    
    // Status
    BOOLEAN IsEnabled;
    BOOLEAN IsCompiled;
    UINT16 Reserved;
} BE_LOADED_RULE, *PBE_LOADED_RULE;

// ============================================================================
// BEHAVIORAL ENGINE GLOBAL STATE
// ============================================================================

/**
 * @brief Behavioral engine global state.
 */
typedef struct _BEHAVIOR_ENGINE_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;
    
    // Configuration
    UINT32 ChainTimeoutMs;
    UINT32 MaxActiveChains;
    UINT32 MaxEventsPerChain;
    UINT32 CorrelationWindowMs;
    UINT32 HighThreatThreshold;
    UINT32 CriticalThreshold;
    
    // Attack chains
    LIST_ENTRY ActiveChainList;
    ERESOURCE ChainLock;
    UINT32 ActiveChainCount;
    volatile LONG64 NextChainId;
    
    // Process contexts
    LIST_ENTRY ProcessContextList;
    ERESOURCE ProcessLock;
    UINT32 ProcessContextCount;
    UINT32 Reserved2;
    
    // Rules
    LIST_ENTRY LoadedRuleList;
    ERESOURCE RuleLock;
    UINT32 LoadedRuleCount;
    UINT32 EnabledRuleCount;
    
    // Event queue
    LIST_ENTRY PendingEventQueue;
    KSPIN_LOCK EventQueueLock;
    UINT32 PendingEventCount;
    UINT32 MaxPendingEvents;
    
    // Worker thread
    PETHREAD WorkerThread;
    KEVENT WorkerWakeEvent;
    KEVENT WorkerStopEvent;
    BOOLEAN WorkerStopping;
    UINT8 Reserved3[3];
    
    // Lookaside lists
    NPAGED_LOOKASIDE_LIST EventLookaside;
    NPAGED_LOOKASIDE_LIST ChainLookaside;
    NPAGED_LOOKASIDE_LIST EntryLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    
    // Statistics
    volatile LONG64 TotalEventsProcessed;
    volatile LONG64 TotalEventsCorrelated;
    volatile LONG64 TotalChainsCreated;
    volatile LONG64 TotalRuleMatches;
    volatile LONG64 TotalThreatsDetected;
    volatile LONG64 TotalThreatsBlocked;
    volatile LONG64 EventsDropped;
    
    // Timing
    UINT64 LastChainCleanupTime;
    UINT64 LastStatisticsReportTime;
} BEHAVIOR_ENGINE_GLOBALS, *PBEHAVIOR_ENGINE_GLOBALS;

// ============================================================================
// SAFE STATISTICS STRUCTURE (FOR EXTERNAL EXPOSURE)
// ============================================================================

/**
 * @brief Safe behavioral engine statistics for external reporting.
 *
 * This structure contains ONLY safe-to-expose statistics fields.
 * It explicitly excludes:
 * - Internal pointers (thread objects, list heads)
 * - Lock states and synchronization primitives
 * - Memory allocator structures
 * - Any data that could aid kernel exploitation
 */
typedef struct _BEHAVIOR_ENGINE_STATISTICS {
    // Configuration (read-only)
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;

    UINT32 ChainTimeoutMs;
    UINT32 MaxActiveChains;
    UINT32 MaxEventsPerChain;
    UINT32 CorrelationWindowMs;
    UINT32 HighThreatThreshold;
    UINT32 CriticalThreshold;

    // Current state counts
    UINT32 ActiveChainCount;
    UINT32 ProcessContextCount;
    UINT32 LoadedRuleCount;
    UINT32 EnabledRuleCount;
    UINT32 PendingEventCount;
    UINT32 MaxPendingEvents;

    // Lifetime statistics (monotonically increasing)
    LONG64 TotalEventsProcessed;
    LONG64 TotalEventsCorrelated;
    LONG64 TotalChainsCreated;
    LONG64 TotalRuleMatches;
    LONG64 TotalThreatsDetected;
    LONG64 TotalThreatsBlocked;
    LONG64 EventsDropped;

    // Timing information
    UINT64 LastChainCleanupTime;
    UINT64 LastStatisticsReportTime;
    UINT64 EngineUptimeMs;
} BEHAVIOR_ENGINE_STATISTICS, *PBEHAVIOR_ENGINE_STATISTICS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the behavioral engine.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineInitialize(VOID);

/**
 * @brief Shutdown the behavioral engine.
 */
VOID
BeEngineShutdown(VOID);

/**
 * @brief Enable or disable the behavioral engine.
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineSetEnabled(
    _In_ BOOLEAN Enable
    );

// ============================================================================
// PUBLIC API - EVENT SUBMISSION
// ============================================================================

/**
 * @brief Submit behavioral event for analysis.
 * @param EventType Event type.
 * @param Category Event category.
 * @param ProcessId Source process ID.
 * @param EventData Event-specific data.
 * @param EventDataSize Size of event data.
 * @param ThreatScore Pre-computed threat score (0 to compute automatically).
 * @param IsBlocking TRUE if event requires synchronous decision.
 * @param Response Output response action (if blocking).
 * @return STATUS_SUCCESS on success.
 */
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
    );

/**
 * @brief Submit process creation event.
 * @param ProcessId New process ID.
 * @param ParentProcessId Parent process ID.
 * @param ImagePath Process image path.
 * @param CommandLine Process command line.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineProcessCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine
    );

/**
 * @brief Submit process termination event.
 * @param ProcessId Terminated process ID.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineProcessTerminate(
    _In_ UINT32 ProcessId
    );

// ============================================================================
// PUBLIC API - ATTACK CHAIN MANAGEMENT
// ============================================================================

/**
 * @brief Get attack chain by ID.
 * @param ChainId Chain ID.
 * @param Chain Output chain pointer.
 * @return STATUS_SUCCESS if found.
 */
NTSTATUS
BeEngineGetChain(
    _In_ UINT64 ChainId,
    _Out_ PBE_ATTACK_CHAIN* Chain
    );

/**
 * @brief Get attack chains for process.
 * @param ProcessId Process ID.
 * @param Chains Output array of chain pointers.
 * @param MaxChains Maximum chains to return.
 * @param ChainCount Output number of chains found.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineGetProcessChains(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxChains, *ChainCount) PBE_ATTACK_CHAIN* Chains,
    _In_ UINT32 MaxChains,
    _Out_ PUINT32 ChainCount
    );

/**
 * @brief Release chain reference.
 * @param Chain Chain to release.
 */
VOID
BeEngineReleaseChain(
    _In_ PBE_ATTACK_CHAIN Chain
    );

/**
 * @brief Mark chain as false positive.
 * @param ChainId Chain ID.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineMarkChainFalsePositive(
    _In_ UINT64 ChainId
    );

/**
 * @brief Remediate attack chain (kill processes, quarantine files).
 * @param ChainId Chain ID.
 * @param RemediationFlags Remediation options.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineRemediateChain(
    _In_ UINT64 ChainId,
    _In_ UINT32 RemediationFlags
    );

// Remediation flags
#define BE_REMEDIATE_TERMINATE_PRIMARY    0x00000001
#define BE_REMEDIATE_TERMINATE_RELATED    0x00000002
#define BE_REMEDIATE_QUARANTINE_FILES     0x00000004
#define BE_REMEDIATE_BLOCK_NETWORK        0x00000008
#define BE_REMEDIATE_ROLLBACK_REGISTRY    0x00000010
#define BE_REMEDIATE_ROLLBACK_FILES       0x00000020  // Ransomware file rollback via FileBackupEngine

// ============================================================================
// PUBLIC API - PROCESS CONTEXT
// ============================================================================

/**
 * @brief Get behavioral context for process.
 * @param ProcessId Process ID.
 * @param Context Output context pointer.
 * @return STATUS_SUCCESS if found.
 */
NTSTATUS
BeEngineGetProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PBE_PROCESS_CONTEXT* Context
    );

/**
 * @brief Release process context reference.
 * @param Context Context to release.
 */
VOID
BeEngineReleaseProcessContext(
    _In_ PBE_PROCESS_CONTEXT Context
    );

/**
 * @brief Get behavioral risk score for process.
 * @param ProcessId Process ID.
 * @param Score Output risk score (0-1000).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineGetProcessRiskScore(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 Score
    );

// ============================================================================
// PUBLIC API - RULES
// ============================================================================

/**
 * @brief Load behavioral detection rules.
 * @param Rules Array of rules.
 * @param RuleCount Number of rules.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineLoadRules(
    _In_reads_(RuleCount) PATTACK_DETECTION_RULE Rules,
    _In_ UINT32 RuleCount
    );

/**
 * @brief Enable or disable rule.
 * @param RuleId Rule ID.
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineSetRuleEnabled(
    _In_ UINT32 RuleId,
    _In_ BOOLEAN Enable
    );

/**
 * @brief Get rule match statistics.
 * @param RuleId Rule ID.
 * @param TotalMatches Output total matches.
 * @param LastMatchTime Output last match time.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineGetRuleStats(
    _In_ UINT32 RuleId,
    _Out_ PUINT32 TotalMatches,
    _Out_ PUINT64 LastMatchTime
    );

// ============================================================================
// PUBLIC API - MITRE ATT&CK
// ============================================================================

/**
 * @brief Map event to MITRE ATT&CK technique.
 * @param EventType Event type.
 * @param EventData Event-specific data.
 * @param TechniqueId Output technique ID.
 * @param Tactic Output primary tactic.
 * @return STATUS_SUCCESS if mapping found.
 */
NTSTATUS
BeEngineMapToMitre(
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_opt_ PVOID EventData,
    _Out_ PUINT32 TechniqueId,
    _Out_ PMITRE_TACTIC Tactic
    );

/**
 * @brief Get observed techniques for process.
 * @param ProcessId Process ID.
 * @param TechniqueIds Output array of technique IDs.
 * @param MaxTechniques Maximum techniques to return.
 * @param TechniqueCount Output number of techniques.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineGetProcessTechniques(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxTechniques, *TechniqueCount) PUINT32 TechniqueIds,
    _In_ UINT32 MaxTechniques,
    _Out_ PUINT32 TechniqueCount
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get behavioral engine statistics (SAFE VERSION).
 *
 * Returns only safe-to-expose statistics. Use this for user-mode
 * IOCTL responses to avoid kernel information disclosure.
 *
 * @param Stats Output statistics structure.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineGetStatisticsSafe(
    _Out_ PBEHAVIOR_ENGINE_STATISTICS Stats
    );

/**
 * @brief Get behavioral engine statistics (INTERNAL ONLY).
 *
 * WARNING: This function returns internal state including pointers.
 * DO NOT expose this to user-mode. Use BeEngineGetStatisticsSafe instead.
 *
 * @param Stats Output statistics.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
BeEngineGetStatistics(
    _Out_ PBEHAVIOR_ENGINE_GLOBALS Stats
    );
