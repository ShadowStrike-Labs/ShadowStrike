// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PROCESS NOTIFICATION IMPLEMENTATION
===============================================================================

@file ProcessNotify.c
@brief Enterprise-grade process creation/termination interception for kernel EDR.

This module provides comprehensive process monitoring via PsSetCreateProcessNotifyRoutineEx:
- Full process context capture (token, privileges, parent chain, command line)
- PPID spoofing detection (parent process ID manipulation)
- Command line analysis for suspicious patterns (encoded commands, LOLBins)
- Elevated privilege monitoring and privilege escalation detection
- Session isolation verification (cross-session process creation)
- Process hollowing/injection detection signals
- Known malware ancestry detection
- Asynchronous event buffering with rate limiting
- Per-process tracking with efficient caching
- IRQL-safe operations throughout

Detection Techniques Covered (MITRE ATT&CK):
- T1055: Process Injection (hollowing detection)
- T1134: Access Token Manipulation (token theft detection)
- T1134.004: Parent PID Spoofing
- T1059: Command and Scripting Interpreter (encoded commands)
- T1218: System Binary Proxy Execution (LOLBins)
- T1548: Abuse Elevation Control Mechanism
- T1543: Create or Modify System Process

Performance Characteristics:
- O(1) process context lookup via hash table
- Lock-free statistics using InterlockedXxx
- Lookaside lists for high-frequency allocations
- Early exit for trusted/excluded processes
- Configurable analysis depth
- Rate limiting for user-mode notifications

Lock Ordering (MUST BE FOLLOWED):
1. ProcessListLock (outer)
2. HashTable[n].Lock (inner)
Never acquire ProcessListLock while holding a bucket lock.

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "ProcessNotify.h"
#include "ProcessAnalyzer.h"
#include "ProcessRelationship.h"
#include "ThreadNotify.h"
#include "ParentChainTracker.h"
#include "CommandLineParser.h"
#include "TokenAnalyzer.h"
#include "../../Core/Globals.h"
#include "../../Communication/CommPort.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Behavioral/ThreatScoring.h"
#include "../../Behavioral/BehaviorEngine.h"
#include "../../Behavioral/PatternMatcher.h"
#include "WSLMonitor.h"
#include "AppControl.h"
#include "ClipboardMonitor.h"
#include "../../../Shared/VerdictTypes.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Core/DriverEntry.h"
#include "../../Performance/PerformanceMonitor.h"
#include "../../Performance/ResourceThrottling.h"
#include "../../Sync/TimerManager.h"
#include "../FileSystem/FileBackupEngine.h"
#include "../FileSystem/FileSystemCallbacks.h"
#include "../FileSystem/PreSetInfo.h"
#include "../Object/ObjectCallback.h"
#include "../Object/ProcessProtection.h"
#include "AmsiBypassDetector.h"
#include "EnvironmentMonitor.h"
#include "HandleTracker.h"
#include "ImageNotify.h"
#include "PrivilegeMonitor.h"
#include "../Registry/RegistryCallback.h"
#include "../../Communication/MessageHandler.h"
#include "../../Communication/ScanBridge.h"
#include "../../Communication/TelemetryBuffer.h"
#include "../../ALPC/AlpcPortMonitor.h"
#include "../../ETW/ETWConsumer.h"
#include "../../ETW/ETWProvider.h"
#include "../../ETW/TelemetryEvents.h"
#include "../../Memory/MemoryMonitor.h"
#include "../../Memory/HollowingDetector.h"
#include "../../Syscall/SyscallMonitor.h"
#include <ntstrsafe.h>

//
// Forward-declare C2Detection and ConnectionTracker APIs to avoid
// including NetworkFilter.h (which pulls ConnectionTracker.h â€”
// PCT_TRACKER/PCT_STATISTICS collide with ParentChainTracker.h).
//
typedef struct _C2_DETECTOR C2_DETECTOR, *PC2_DETECTOR;
VOID C2ProcessTerminated(_In_ PC2_DETECTOR Detector, _In_ HANDLE ProcessId);
PC2_DETECTOR NfFilterGetC2Detector(VOID);

typedef struct _CT_TRACKER CT_TRACKER, *PCONNECTION_TRACKER;
VOID CtProcessTerminated(_In_ PCONNECTION_TRACKER Tracker, _In_ HANDLE ProcessId);
struct _CT_TRACKER* NfFilterGetConnectionTracker(VOID);

// HandleProtection forward-declare (avoid pulling SelfProtection headers
// which would introduce cross-subsystem header coupling)
VOID HpProcessTerminated(_In_ PHP_PROTECTION_ENGINE Engine, _In_ HANDLE ProcessId);

// SelfProtect forward-declare: cleanup protected process entry on termination.
// Without this call, PEPROCESS reference leaks and PID slot stays occupied.
VOID ShadowStrikeUnprotectProcess(_In_ HANDLE ProcessId);

typedef struct _DX_DETECTOR DX_DETECTOR, *PDX_DETECTOR;
VOID DxProcessTerminated(_In_ PDX_DETECTOR Detector, _In_ HANDLE ProcessId);
struct _DX_DETECTOR* NfFilterGetDxDetector(VOID);

typedef struct _DNS_MONITOR DNS_MONITOR, *PDNS_MONITOR;
VOID DnsProcessTerminated(_In_ PDNS_MONITOR Monitor, _In_ HANDLE ProcessId);
struct _DNS_MONITOR* NfFilterGetDnsMonitor(VOID);

typedef struct _AU_PROTECTOR AU_PROTECTOR, *PAU_PROTECTOR;
VOID AuUnprotectProcess(_In_ PAU_PROTECTOR Protector, _In_ HANDLE ProcessId);
PAU_PROTECTOR ShadowStrikeGetAntiUnloadProtector(VOID);

static VOID PnpCleanupStaleContexts(VOID);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeInitializeProcessMonitoring)
//
// ShadowStrikeCleanupProcessMonitoring removed from PAGE:
// Uses KeAcquireSpinLock (NotificationLock) internally.
// DV Force IRQL Checking trims PAGE code at DISPATCH_LEVEL -> 0xD1.
//
// PnpCleanupStaleContexts also removed from PAGE for consistency:
// Called from cleanup paths that may run alongside spinlock-holding code.
//
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PN_POOL_TAG                     'TNPP'  // PPNT reversed
#define PN_CONTEXT_POOL_TAG             'xCNP'  // PNCx
#define PN_WORK_ITEM_TAG                'WKNP'  // PNWK
#define PN_MAX_PROCESS_CONTEXTS         4096
#define PN_MAX_PENDING_NOTIFICATIONS    1024
#define PN_CLEANUP_INTERVAL_MS          60000   // 1 minute
#define PN_CONTEXT_TIMEOUT_MS           300000  // 5 minutes
#define PN_MAX_COMMAND_LINE_CAPTURE     8192
#define PN_MAX_IMAGE_PATH_CAPTURE       2048

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

//
// Forward declaration for undocumented but supported API (Win8.1+)
// PsGetProcessSignatureLevel returns VOID and populates output params
//
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
NTKERNELAPI
VOID
PsGetProcessSignatureLevel(
    _In_ PEPROCESS Process,
    _Out_ PUCHAR SignatureLevel,
    _Out_ PUCHAR SectionSignatureLevel
    );
#endif
#define PN_USER_MODE_TIMEOUT_MS         5000    // 5 second timeout for user-mode
#define PN_MAX_NOTIFICATIONS_PER_SECOND 1000    // Rate limit
#define PN_RATE_LIMIT_WINDOW_MS         1000    // 1 second window
#define PN_MAX_PENDING_POOL_BYTES       (4 * 1024 * 1024)  // 4MB max pending

//
// Suspicion score thresholds
//
#define PN_SUSPICION_LOW                15
#define PN_SUSPICION_MEDIUM             35
#define PN_SUSPICION_HIGH               60
#define PN_SUSPICION_CRITICAL           85

//
// Process flags
//
#define PN_PROC_FLAG_ANALYZED           0x00000001
#define PN_PROC_FLAG_SUSPICIOUS         0x00000002
#define PN_PROC_FLAG_PPID_SPOOFED       0x00000004
#define PN_PROC_FLAG_ELEVATED           0x00000008
#define PN_PROC_FLAG_SYSTEM             0x00000010
#define PN_PROC_FLAG_SERVICE            0x00000020
#define PN_PROC_FLAG_LOLBIN             0x00000040
#define PN_PROC_FLAG_ENCODED_CMD        0x00000080
#define PN_PROC_FLAG_CROSS_SESSION      0x00000100
#define PN_PROC_FLAG_UNSIGNED           0x00000200
#define PN_PROC_FLAG_BLOCKED            0x00000400
#define PN_PROC_FLAG_TRUSTED            0x00000800
#define PN_PROC_FLAG_REMOTE_THREAD      0x00001000
#define PN_PROC_FLAG_HAS_DEBUG_PRIV     0x00002000
#define PN_PROC_FLAG_HAS_IMPERSONATE    0x00004000
#define PN_PROC_FLAG_HAS_TCB            0x00008000
#define PN_PROC_FLAG_HAS_ASSIGN_TOKEN   0x00010000
#define PN_PROC_FLAG_SIGNATURE_VALID    0x00020000
#define PN_PROC_FLAG_HOLLOWED           0x00040000

//
// Behavior flags for command-line analysis
//
#define PN_BEHAVIOR_SUSPICIOUS_PS       0x00000001
#define PN_BEHAVIOR_DOWNLOAD_CRADLE     0x00000002
#define PN_BEHAVIOR_SUSPICIOUS_CMD      0x00000004
#define PN_BEHAVIOR_LONG_CMDLINE        0x00000008
#define PN_BEHAVIOR_BASE64_ENCODED      0x00000010
#define PN_BEHAVIOR_REFLECTION_LOAD     0x00000020
#define PN_BEHAVIOR_ENV_DLL_HIJACK      0x00000040
#define PN_BEHAVIOR_ENV_ENCODED_VALUE   0x00000080
#define PN_BEHAVIOR_HANDLE_INJECTION    0x00000100
#define PN_BEHAVIOR_HANDLE_CRED_ACCESS  0x00000200
#define PN_BEHAVIOR_HANDLE_TOKEN_STEAL  0x00000400

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Per-process context for tracking
//
typedef struct _PN_PROCESS_CONTEXT {
    //
    // Identification
    //
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    HANDLE CreatingProcessId;
    HANDLE CreatingThreadId;
    PEPROCESS ProcessObject;

    //
    // Process information - Buffers are always null-terminated
    //
    UNICODE_STRING ImagePath;
    UNICODE_STRING CommandLine;
    UNICODE_STRING ImageFileName;   // Just the filename

    //
    // Timing
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER TerminateTime;

    //
    // Session info
    //
    ULONG SessionId;
    ULONG ParentSessionId;

    //
    // Token/Security info
    //
    ULONG IntegrityLevel;
    BOOLEAN IsElevated;
    BOOLEAN IsSystem;
    BOOLEAN IsService;
    BOOLEAN HasDebugPrivilege;
    BOOLEAN HasImpersonatePrivilege;
    BOOLEAN HasTcbPrivilege;
    BOOLEAN HasAssignPrimaryTokenPrivilege;
    BOOLEAN HasLoadDriverPrivilege;
    BOOLEAN IsSignatureValid;
    LUID AuthenticationId;

    //
    // Analysis results
    //
    ULONG Flags;
    ULONG SuspicionScore;
    ULONG BehaviorFlags;

    //
    // Parent spoofing detection
    //
    BOOLEAN IsPpidSpoofed;
    HANDLE RealParentProcessId;     // Actual parent from kernel

    //
    // Reference counting - must use interlocked operations
    //
    volatile LONG RefCount;

    //
    // List linkage - protected by respective locks
    //
    LIST_ENTRY ListEntry;           // Protected by ProcessListLock
    LIST_ENTRY HashEntry;           // Protected by Bucket->Lock

    //
    // Insertion tracking for safety
    //
    volatile LONG InsertedInList;
    volatile LONG InsertedInHash;

} PN_PROCESS_CONTEXT, *PPN_PROCESS_CONTEXT;

//
// Process notification queue entry
//
typedef struct _PN_NOTIFICATION_ENTRY {
    LIST_ENTRY ListEntry;
    BOOLEAN IsCreation;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    LARGE_INTEGER Timestamp;
    ULONG SuspicionScore;
    ULONG Flags;
} PN_NOTIFICATION_ENTRY, *PPN_NOTIFICATION_ENTRY;

//
// Hash table bucket
//
#define PN_HASH_BUCKET_COUNT    256

typedef struct _PN_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
} PN_HASH_BUCKET, *PPN_HASH_BUCKET;

//
// Rate limiting structure
//
typedef struct _PN_RATE_LIMITER {
    volatile LONG64 WindowStartTime;    // In 100ns units
    volatile LONG NotificationsInWindow;
    volatile LONG DroppedNotifications;
} PN_RATE_LIMITER, *PPN_RATE_LIMITER;

//
// Pool tracking for memory limits
//
typedef struct _PN_POOL_TRACKER {
    volatile LONG64 CurrentAllocation;
    volatile LONG64 PeakAllocation;
    LONG64 MaxAllocation;
} PN_POOL_TRACKER, *PPN_POOL_TRACKER;

//
// Process monitor configuration - immutable after initialization
// All fields are read atomically or are inherently atomic (BOOLEAN/ULONG)
//
typedef struct _PN_CONFIG {
    BOOLEAN EnablePpidSpoofingDetection;
    BOOLEAN EnableCommandLineAnalysis;
    BOOLEAN EnableTokenAnalysis;
    BOOLEAN EnableParentChainTracking;
    BOOLEAN EnablePrivilegeMonitoring;
    BOOLEAN EnableSignatureVerification;
    BOOLEAN BlockSuspiciousProcesses;
    ULONG MinBlockScore;
    ULONG AnalysisTimeoutMs;
    ULONG MaxNotificationsPerSecond;
    //
    // Configuration is frozen after initialization
    //
    volatile BOOLEAN Frozen;
} PN_CONFIG, *PPN_CONFIG;

//
// Process monitor state
//
typedef struct _PN_MONITOR_STATE {
    //
    // Initialization
    //
    volatile BOOLEAN Initialized;

    //
    // Process context tracking
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;

    //
    // Hash table for fast lookup
    //
    PN_HASH_BUCKET HashTable[PN_HASH_BUCKET_COUNT];

    //
    // Pending notification queue
    //
    LIST_ENTRY NotificationQueue;
    KSPIN_LOCK NotificationLock;
    volatile LONG NotificationCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    NPAGED_LOOKASIDE_LIST NotificationLookaside;
    volatile BOOLEAN LookasideInitialized;

    //
    // Cleanup timer (managed by TimerManager)
    //
    ULONG CleanupTimerId;
    volatile LONG CleanupWorkPending;

    //
    // Rate limiting
    //
    PN_RATE_LIMITER RateLimiter;

    //
    // Pool tracking
    //
    PN_POOL_TRACKER PoolTracker;

    //
    // Sub-analyzers (optional integration)
    //
    PVOID ProcessAnalyzer;      // PPA_ANALYZER
    PVOID ParentChainTracker;   // PPCT_TRACKER
    PVOID PrivilegeMonitor;     // PPM_MONITOR
    PVOID CommandLineParser;    // PCLP_PARSER
    PVOID TokenAnalyzer;        // PTA_ANALYZER

    //
    // Centralized threat scoring engine
    // Provides unified multi-factor threat assessment across all detections
    //
    PTS_SCORING_ENGINE ThreatScoringEngine;

    //
    // Statistics - all use interlocked operations
    // Note: LONG64 can overflow after ~9 quintillion operations
    // This is acceptable for practical purposes (would take centuries)
    //
    struct {
        volatile LONG64 ProcessCreations;
        volatile LONG64 ProcessTerminations;
        volatile LONG64 ProcessesBlocked;
        volatile LONG64 PpidSpoofingDetected;
        volatile LONG64 ElevatedProcesses;
        volatile LONG64 SuspiciousProcesses;
        volatile LONG64 EncodedCommands;
        volatile LONG64 LOLBinsDetected;
        volatile LONG64 CrossSessionCreations;
        volatile LONG64 AnalysisErrors;
        volatile LONG64 RateLimitDrops;
        volatile LONG64 PoolLimitDrops;
        volatile LONG64 UserModeTimeouts;
        volatile LONG64 SecurityChecksTriggered;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration - frozen after init
    //
    PN_CONFIG Config;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

} PN_MONITOR_STATE, *PPN_MONITOR_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PN_MONITOR_STATE g_ProcessMonitor = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPN_PROCESS_CONTEXT
PnpAllocateProcessContext(
    VOID
    );

static VOID
PnpFreeProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static PPN_PROCESS_CONTEXT
PnpLookupProcessContext(
    _In_ HANDLE ProcessId
    );

static NTSTATUS
PnpInsertProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static VOID
PnpRemoveProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static VOID
PnpReferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    );

static VOID
PnpDereferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    );

static ULONG
PnpHashProcessId(
    _In_ HANDLE ProcessId
    );

static NTSTATUS
PnpCaptureProcessInfo(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PPN_PROCESS_CONTEXT Context
    );

static NTSTATUS
PnpAnalyzeProcess(
    _Inout_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpDetectPpidSpoofing(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

static ULONG
PnpCalculateSuspicionScore(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static NTSTATUS
PnpSendProcessNotification(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ BOOLEAN IsCreation,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

static VOID
PnpHandleProcessTermination(
    _In_ HANDLE ProcessId
    );

static VOID
PnpCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

static VOID
PnpCleanupStaleContexts(
    VOID
    );

static NTSTATUS
PnpCaptureTokenInfo(
    _In_ PEPROCESS Process,
    _Out_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpIsKnownSystemProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PEPROCESS Process
    );

static BOOLEAN
PnpIsTrustedProcess(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpCheckParentSessionMatch(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpCheckRateLimit(
    VOID
    );

static BOOLEAN
PnpCheckPoolLimit(
    _In_ SIZE_T AllocationSize
    );

static VOID
PnpTrackPoolAllocation(
    _In_ SIZE_T Size
    );

static VOID
PnpTrackPoolFree(
    _In_ SIZE_T Size
    );

static BOOLEAN
PnpSafeWcsStrI(
    _In_ PCWCH Buffer,
    _In_ USHORT BufferLengthBytes,
    _In_ PCWSTR Pattern
    );

static NTSTATUS
PnpVerifyImageSignature(
    _In_ PPN_PROCESS_CONTEXT Context
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitializeProcessMonitoring(
    VOID
    )
/*++
Routine Description:
    Initializes the process monitoring subsystem.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    ULONG i;

    PAGED_CODE();

    if (g_ProcessMonitor.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_ProcessMonitor, sizeof(PN_MONITOR_STATE));

    //
    // Initialize process list
    //
    InitializeListHead(&g_ProcessMonitor.ProcessList);
    ExInitializePushLock(&g_ProcessMonitor.ProcessListLock);

    //
    // Initialize hash table
    //
    for (i = 0; i < PN_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_ProcessMonitor.HashTable[i].List);
        ExInitializePushLock(&g_ProcessMonitor.HashTable[i].Lock);
    }

    //
    // Initialize notification queue
    //
    InitializeListHead(&g_ProcessMonitor.NotificationQueue);
    KeInitializeSpinLock(&g_ProcessMonitor.NotificationLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_ProcessMonitor.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PN_PROCESS_CONTEXT),
        PN_CONTEXT_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_ProcessMonitor.NotificationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PN_NOTIFICATION_ENTRY),
        PN_POOL_TAG,
        0
        );

    g_ProcessMonitor.LookasideInitialized = TRUE;

    //
    // Initialize pool tracking
    //
    g_ProcessMonitor.PoolTracker.MaxAllocation = PN_MAX_PENDING_POOL_BYTES;
    g_ProcessMonitor.PoolTracker.CurrentAllocation = 0;
    g_ProcessMonitor.PoolTracker.PeakAllocation = 0;

    //
    // Initialize rate limiter
    //
    KeQuerySystemTime((PLARGE_INTEGER)&g_ProcessMonitor.RateLimiter.WindowStartTime);
    g_ProcessMonitor.RateLimiter.NotificationsInWindow = 0;
    g_ProcessMonitor.RateLimiter.DroppedNotifications = 0;

    //
    // Initialize default configuration
    // Configuration is FROZEN after this point - reads are safe without locks
    //
    g_ProcessMonitor.Config.EnablePpidSpoofingDetection = TRUE;
    g_ProcessMonitor.Config.EnableCommandLineAnalysis = TRUE;
    g_ProcessMonitor.Config.EnableTokenAnalysis = TRUE;
    g_ProcessMonitor.Config.EnableParentChainTracking = TRUE;

    //
    // Acquire reference to ParentChainTracker from ProcessAnalyzer
    //
    g_ProcessMonitor.ParentChainTracker = (PVOID)PaGetParentChainTracker();
    g_ProcessMonitor.PrivilegeMonitor = (PVOID)PaGetPrivilegeMonitor();
    g_ProcessMonitor.TokenAnalyzer = (PVOID)PaGetTokenAnalyzer();
    g_ProcessMonitor.ProcessAnalyzer = (PVOID)ShadowStrikeGetProcessAnalyzer();
    g_ProcessMonitor.Config.EnablePrivilegeMonitoring = TRUE;
    g_ProcessMonitor.Config.EnableSignatureVerification = TRUE;
    g_ProcessMonitor.Config.BlockSuspiciousProcesses = FALSE;  // Audit mode by default
    g_ProcessMonitor.Config.MinBlockScore = PN_SUSPICION_CRITICAL;
    g_ProcessMonitor.Config.AnalysisTimeoutMs = PN_USER_MODE_TIMEOUT_MS;
    g_ProcessMonitor.Config.MaxNotificationsPerSecond = PN_MAX_NOTIFICATIONS_PER_SECOND;

    //
    // Freeze configuration - must be set with memory barrier
    //
    MemoryBarrier();
    g_ProcessMonitor.Config.Frozen = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_ProcessMonitor.Stats.StartTime);

    //
    // Initialize centralized threat scoring engine
    // This provides unified multi-factor threat assessment with:
    // - O(1) process lookup via hash table
    // - PID reuse protection via process creation time validation
    // - Factor aging and decay for temporal relevance
    // - Configurable thresholds for verdicts (suspicious/malicious/blocked)
    //
    //
    // Use the centralized ThreatScoring engine from DriverEntry
    // instead of creating a duplicate instance (split-brain fix).
    //
    g_ProcessMonitor.ThreatScoringEngine = (PTS_SCORING_ENGINE)ShadowStrikeGetThreatScoringEngine();
    if (g_ProcessMonitor.ThreatScoringEngine == NULL) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/ProcessNotify] ThreatScoring engine not available from DriverEntry\n"
            );
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.ContextLookaside);
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside);
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Configure threat scoring thresholds aligned with our suspicion levels
    // Suspicious: 50 (PN_SUSPICION_MEDIUM maps roughly here)
    // Malicious: 80 (PN_SUSPICION_HIGH area)
    // Blocked: 95 (PN_SUSPICION_CRITICAL)
    //
    TsSetThresholds(
        g_ProcessMonitor.ThreatScoringEngine,
        50,     // SuspiciousThreshold
        80,     // MaliciousThreshold
        95      // BlockedThreshold
        );

    //
    // Initialize cleanup timer via centralized TimerManager
    //
    {
        PTM_MANAGER timerManager = ShadowStrikeGetTimerManager();
        if (timerManager != NULL) {
            TM_TIMER_OPTIONS opts = {0};
            opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
            opts.ToleranceMs = 5000;
            opts.Name = "ProcessNotifyCleanup";

            NTSTATUS tmStatus = TmCreatePeriodic(
                timerManager,
                PN_CLEANUP_INTERVAL_MS,
                PnpCleanupTimerCallback,
                NULL,
                &opts,
                &g_ProcessMonitor.CleanupTimerId
            );
            if (!NT_SUCCESS(tmStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/ProcessNotify] Failed to create cleanup timer: 0x%08X\n",
                           tmStatus);
                g_ProcessMonitor.CleanupTimerId = 0;
            }
        } else {
            g_ProcessMonitor.CleanupTimerId = 0;
        }
    }

    //
    // Mark as initialized with memory barrier
    //
    MemoryBarrier();
    g_ProcessMonitor.Initialized = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ProcessNotify] Process monitoring initialized (v3.0)\n"
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
ShadowStrikeCleanupProcessMonitoring(
    VOID
    )
/*++
Routine Description:
    Cleans up the process monitoring subsystem.

    This function is designed to be safe against races with the callback
    and cleanup DPC/work item.
--*/
{
    PLIST_ENTRY Entry;
    PPN_PROCESS_CONTEXT Context;
    PPN_NOTIFICATION_ENTRY Notification;
    KIRQL OldIrql;
    LIST_ENTRY FreeList;

    if (!g_ProcessMonitor.Initialized) {
        return;
    }

    //
    // Signal shutdown first - prevents new work from starting
    //
    InterlockedExchange8((volatile CHAR*)&g_ProcessMonitor.ShutdownRequested, TRUE);
    MemoryBarrier();
    InterlockedExchange8((volatile CHAR*)&g_ProcessMonitor.Initialized, FALSE);
    MemoryBarrier();

    //
    // Cancel cleanup timer via TimerManager.
    // TmCancel(Wait=TRUE) blocks until any in-flight callback completes.
    //
    if (g_ProcessMonitor.CleanupTimerId != 0) {
        PTM_MANAGER timerManager = ShadowStrikeGetTimerManager();
        if (timerManager != NULL) {
            TmCancel(timerManager, g_ProcessMonitor.CleanupTimerId, TRUE);
        }
        g_ProcessMonitor.CleanupTimerId = 0;
    }

    //
    // Collect all process contexts to free
    // Use proper lock ordering: ProcessListLock first, then bucket locks
    //
    InitializeListHead(&FreeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    //
    // Move all entries to free list
    //
    while (!IsListEmpty(&g_ProcessMonitor.ProcessList)) {
        Entry = RemoveHeadList(&g_ProcessMonitor.ProcessList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Mark as removed from list
        //
        InitializeListHead(&Context->ListEntry);
        InterlockedExchange(&Context->InsertedInList, FALSE);

        InsertTailList(&FreeList, &Context->ListEntry);
        InterlockedDecrement(&g_ProcessMonitor.ProcessCount);
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Now remove from hash tables and free - outside ProcessListLock
    //
    while (!IsListEmpty(&FreeList)) {
        Entry = RemoveHeadList(&FreeList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Remove from hash table under correct bucket lock
        //
        if (InterlockedCompareExchange(&Context->InsertedInHash, FALSE, TRUE)) {
            ULONG BucketIndex = PnpHashProcessId(Context->ProcessId);
            PPN_HASH_BUCKET Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Bucket->Lock);

            if (!IsListEmpty(&Context->HashEntry)) {
                RemoveEntryList(&Context->HashEntry);
                InitializeListHead(&Context->HashEntry);
            }

            ExReleasePushLockExclusive(&Bucket->Lock);
            KeLeaveCriticalRegion();
        }

        //
        // Free the context
        //
        PnpFreeProcessContext(Context);
    }

    //
    // Free pending notifications
    //
    KeAcquireSpinLock(&g_ProcessMonitor.NotificationLock, &OldIrql);

    while (!IsListEmpty(&g_ProcessMonitor.NotificationQueue)) {
        Entry = RemoveHeadList(&g_ProcessMonitor.NotificationQueue);
        Notification = CONTAINING_RECORD(Entry, PN_NOTIFICATION_ENTRY, ListEntry);
        ExFreeToNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside, Notification);
    }

    KeReleaseSpinLock(&g_ProcessMonitor.NotificationLock, OldIrql);

    //
    // Clear reference to centralized threat scoring engine
    // DriverEntry owns the lifecycle â€” no TsShutdown here.
    //
    g_ProcessMonitor.ThreatScoringEngine = NULL;

    //
    // Delete lookaside lists - safe now that all contexts are freed
    //
    if (g_ProcessMonitor.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.ContextLookaside);
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside);
        g_ProcessMonitor.LookasideInitialized = FALSE;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ProcessNotify] Process monitoring shutdown. "
        "Stats: Created=%lld, Terminated=%lld, Blocked=%lld, PpidSpoof=%lld, "
        "RateLimitDrops=%lld, PoolLimitDrops=%lld\n",
        g_ProcessMonitor.Stats.ProcessCreations,
        g_ProcessMonitor.Stats.ProcessTerminations,
        g_ProcessMonitor.Stats.ProcessesBlocked,
        g_ProcessMonitor.Stats.PpidSpoofingDetected,
        g_ProcessMonitor.Stats.RateLimitDrops,
        g_ProcessMonitor.Stats.PoolLimitDrops
        );
}


// ============================================================================
// MAIN CALLBACK IMPLEMENTATION
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
/*++
Routine Description:
    Enterprise-grade process creation/termination callback.

    Registered via PsSetCreateProcessNotifyRoutineEx.

Arguments:
    Process     - Pointer to the process object.
    ProcessId   - ID of the process.
    CreateInfo  - Creation info (NULL for termination).
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PPN_PROCESS_CONTEXT ProcessContext = NULL;
    BOOLEAN IsCreation = (CreateInfo != NULL);
    BOOLEAN ShouldBlock = FALSE;
    ULONG SuspicionScore = 0;

    //
    // Quick validation
    //
    if (Process == NULL) {
        return;
    }

    //
    // Always increment raw statistics (even if not processing)
    //
    if (IsCreation) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessCreations);
        SHADOWSTRIKE_INC_STAT(TotalProcessCreations);
    } else {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessTerminations);
    }

    //
    // Check if we should process this event
    // Read volatile flags with memory barrier
    //
    MemoryBarrier();
    if (!g_ProcessMonitor.Initialized ||
        g_ProcessMonitor.ShutdownRequested) {
        return;
    }

    if (!SHADOWSTRIKE_IS_READY() ||
        !g_DriverData.Config.ProcessMonitorEnabled) {
        return;
    }

    //
    // Enter operation tracking via rundown protection
    //
    if (!SHADOWSTRIKE_ACQUIRE_RUNDOWN()) {
        return;
    }

    SSPM_LATENCY_BEGIN(proc);

    //
    // Report process lifecycle to ResourceThrottling for DoS mitigation.
    // +1 on creation, -1 on termination tracks concurrent process load.
    //
    {
        PRT_THROTTLER rtThrottler = ShadowStrikeGetResourceThrottler();
        if (rtThrottler != NULL) {
            RtReportUsage(rtThrottler, RtResourceProcessCreation,
                          IsCreation ? 1 : -1);
        }
    }

    //
    // Handle process termination
    //
    if (!IsCreation) {
        //
        // Emit process exit event into ETW consumer pipeline
        //
        {
            PEC_CONSUMER EtwConsumer = ShadowStrikeGetETWConsumer();
            if (EtwConsumer != NULL) {
                EcEmitKernelEvent(
                    EtwConsumer,
                    &GUID_KERNEL_PROCESS_PROVIDER,
                    EC_EVENTID_PROCESS_EXIT,
                    4, // Information
                    0xFFFFFFFFFFFFFFFFULL,
                    HandleToULong(ProcessId),
                    HandleToULong(PsGetCurrentThreadId()),
                    NULL, 0);
            }
        }

        //
        // Emit process terminate event to external ETW provider
        //
        EtwWriteProcessEvent(
            EtwEventId_ProcessTerminate,
            HandleToULong(ProcessId),
            0,      // ParentProcessId not available at exit
            NULL,   // ImagePath not readily available at exit
            NULL,   // CommandLine not available at exit
            0, 0, 0);

        //
        // Notify BehaviorEngine of process termination so it can finalize
        // attack chain analysis, flush pending behavioral events, and
        // release the per-process context entry.
        //
        BeEngineProcessTerminate(HandleToULong(ProcessId));

        PnpHandleProcessTermination(ProcessId);
        goto Cleanup;
    }

    //
    // === PROCESS CREATION HANDLING ===
    //

    //
    // Emit process creation event into ETW consumer pipeline
    //
    {
        PEC_CONSUMER EtwConsumer = ShadowStrikeGetETWConsumer();
        if (EtwConsumer != NULL) {
            EcEmitKernelEvent(
                EtwConsumer,
                &GUID_KERNEL_PROCESS_PROVIDER,
                EC_EVENTID_PROCESS_CREATE,
                4, // Information
                0xFFFFFFFFFFFFFFFFULL,
                HandleToULong(ProcessId),
                HandleToULong(PsGetCurrentThreadId()),
                NULL, 0);
        }
    }

    //
    // Emit process creation event to external ETW provider for
    // SIEM/WPA/Event Log consumers
    //
    EtwWriteProcessEvent(
        EtwEventId_ProcessCreate,
        HandleToULong(ProcessId),
        HandleToULong(CreateInfo->ParentProcessId),
        CreateInfo->ImageFileName,
        CreateInfo->CommandLine,
        0, 0, 0);

    //
    // Notify BehaviorEngine of process creation to populate full
    // per-process context (ImagePath, CommandLine, ParentPID, PEPROCESS).
    // This must precede behavioral analysis so BepGetOrCreateProcessContext
    // has complete data for threat scoring and attack chain correlation.
    //
    BeEngineProcessCreate(
        HandleToULong(ProcessId),
        HandleToULong(CreateInfo->ParentProcessId),
        CreateInfo->ImageFileName,
        CreateInfo->CommandLine
    );

    //
    // Classify the new process for automatic protection. Critical system
    // processes (LSASS, CSRSS, services.exe) and EDR/AV processes get
    // registered in the protection cache for handle-access enforcement
    // by the ObjectCallback pre-operation handlers.
    //
    {
        PP_PROCESS_CATEGORY ppCategory = PpCategoryUnknown;
        PP_PROTECTION_LEVEL ppLevel = PpProtectionNone;

        if (NT_SUCCESS(PpClassifyProcess(Process, &ppCategory, &ppLevel)) &&
            ppCategory != PpCategoryUnknown &&
            ppLevel != PpProtectionNone) {
            PpAddProtectedProcess(ProcessId, ppCategory, ppLevel);
        }
    }

    //
    // Check for known system process (skip detailed analysis for performance)
    //
    if (PnpIsKnownSystemProcess(ProcessId, Process)) {
        goto Cleanup;
    }

    //
    // Evaluate process against exclusion patterns and register in
    // trusted PID bitmap/hash if matched. This must happen BEFORE
    // the ShadowStrikeIsProcessExcluded check below so that newly
    // created processes are immediately recognized as trusted.
    //
    ShadowStrikeOnProcessCreate(
        ProcessId,
        CreateInfo->ParentProcessId,
        CreateInfo->ImageFileName
    );

    //
    // Check if process is excluded from behavioral analysis
    //
    if (ShadowStrikeIsProcessExcluded(ProcessId, NULL)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_TRACE_LEVEL,
            "[ShadowStrike/ProcessNotify] PID %lu excluded â€” skipping analysis\n",
            HandleToULong(ProcessId)
            );
        goto Cleanup;
    }

    //
    // Check rate limit before allocating resources
    //
    if (!PnpCheckRateLimit()) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.RateLimitDrops);
        goto Cleanup;
    }

    //
    // Allocate process context
    //
    ProcessContext = PnpAllocateProcessContext();
    if (ProcessContext == NULL) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.AnalysisErrors);
        goto Cleanup;
    }

    //
    // Capture process information
    //
    Status = PnpCaptureProcessInfo(Process, ProcessId, CreateInfo, ProcessContext);
    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.AnalysisErrors);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] Failed to capture process info for PID %lu: 0x%08X\n",
            HandleToULong(ProcessId),
            Status
            );

        goto Cleanup;
    }

    //
    // Register process with centralized threat scoring engine
    // This provides PID reuse protection via creation time validation
    // and enables unified multi-factor threat assessment
    //
    if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
        Status = TsOnProcessCreate(
            g_ProcessMonitor.ThreatScoringEngine,
            ProcessId,
            ProcessContext->CreateTime
            );
        if (!NT_SUCCESS(Status) && Status != STATUS_QUOTA_EXCEEDED) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_TRACE_LEVEL,
                "[ShadowStrike/ProcessNotify] TsOnProcessCreate failed for PID %lu: 0x%08X\n",
                HandleToULong(ProcessId),
                Status
                );
        }
    }

    //
    // Capture token/security information
    //
    if (g_ProcessMonitor.Config.EnableTokenAnalysis) {
        Status = PnpCaptureTokenInfo(Process, ProcessContext);
        if (!NT_SUCCESS(Status)) {
            //
            // Non-fatal - continue with limited info
            //
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_TRACE_LEVEL,
                "[ShadowStrike/ProcessNotify] Token capture failed for PID %lu: 0x%08X\n",
                HandleToULong(ProcessId),
                Status
                );
        }
    }

    //
    // Privilege Escalation Monitoring â€” record baseline privilege state
    // for the new process so we can detect privilege changes over its lifetime.
    // Baselines are captured once at creation; PmCheckForEscalation compares
    // current token state against baseline when triggered externally.
    //
    if (g_ProcessMonitor.Config.EnablePrivilegeMonitoring &&
        g_ProcessMonitor.PrivilegeMonitor != NULL) {

        PPM_MONITOR pmMon = (PPM_MONITOR)g_ProcessMonitor.PrivilegeMonitor;
        NTSTATUS pmStatus = PmRecordBaseline(pmMon, ProcessId);
        if (!NT_SUCCESS(pmStatus) && pmStatus != STATUS_ALREADY_REGISTERED &&
            pmStatus != STATUS_QUOTA_EXCEEDED) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_TRACE_LEVEL,
                "[ShadowStrike/ProcessNotify] PrivilegeMonitor baseline failed for PID %lu: 0x%08X\n",
                HandleToULong(ProcessId),
                pmStatus
                );
        }
    }

    //
    // Detect PPID spoofing
    //
    if (g_ProcessMonitor.Config.EnablePpidSpoofingDetection) {
        if (PnpDetectPpidSpoofing(ProcessContext, CreateInfo)) {
            ProcessContext->IsPpidSpoofed = TRUE;
            ProcessContext->Flags |= PN_PROC_FLAG_PPID_SPOOFED;
            InterlockedIncrement64(&g_ProcessMonitor.Stats.PpidSpoofingDetected);

            //
            // Feed PPID spoofing factor to centralized threat scoring (MITRE T1134.004)
            // Score: 40 - High severity indicator of malicious intent
            //
            if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                TsAddFactor(
                    g_ProcessMonitor.ThreatScoringEngine,
                    ProcessId,
                    TsFactor_MITRE,
                    "T1134.004-PPID-Spoofing",
                    40,
                    "Parent PID spoofing detected - process claims different parent than actual creator"
                    );
            }

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/ProcessNotify] PPID SPOOFING DETECTED! "
                "PID=%lu, ClaimedParent=%lu, RealParent=%lu\n",
                HandleToULong(ProcessId),
                HandleToULong(ProcessContext->ParentProcessId),
                HandleToULong(ProcessContext->RealParentProcessId)
                );
        }
    }

    //
    // Deep PPID Spoofing Validation â€” PctDetectSpoofing uses creation time
    // ordering and PID reuse protection for a more robust check than the
    // simple creator-vs-parent comparison in PnpDetectPpidSpoofing above.
    // This catches sophisticated spoofing where creation times are manipulated.
    //
    if (g_ProcessMonitor.Config.EnablePpidSpoofingDetection &&
        g_ProcessMonitor.ParentChainTracker != NULL) {

        PPCT_TRACKER pctTracker = (PPCT_TRACKER)g_ProcessMonitor.ParentChainTracker;
        BOOLEAN pctSpoofed = FALSE;

        NTSTATUS pctSpStatus = PctDetectSpoofing(
            pctTracker,
            ProcessId,
            CreateInfo->ParentProcessId,
            NULL,
            &pctSpoofed
            );

        if (NT_SUCCESS(pctSpStatus) && pctSpoofed && !ProcessContext->IsPpidSpoofed) {
            ProcessContext->IsPpidSpoofed = TRUE;
            ProcessContext->Flags |= PN_PROC_FLAG_PPID_SPOOFED;
            InterlockedIncrement64(&g_ProcessMonitor.Stats.PpidSpoofingDetected);

            if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                TsAddFactor(
                    g_ProcessMonitor.ThreatScoringEngine,
                    ProcessId,
                    TsFactor_MITRE,
                    "T1134.004-DeepPPID",
                    50,
                    "PPID spoofing detected via creation-time ordering analysis"
                    );
            }

            BeEngineSubmitEvent(
                BehaviorEvent_SuspiciousParentChild,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(ProcessId),
                &pctSpoofed,
                sizeof(BOOLEAN),
                80,
                FALSE,
                NULL
                );
        }
    }

    //
    // Parent Chain Analysis â€” build process ancestry chain and detect
    // suspicious parent-child patterns (T1218 LOLBins, T1059 script hosts,
    // Officeâ†’shell, Browserâ†’shell, chain depth anomalies)
    //
    if (g_ProcessMonitor.Config.EnableParentChainTracking &&
        g_ProcessMonitor.ParentChainTracker != NULL) {

        PPCT_TRACKER pctTracker = (PPCT_TRACKER)g_ProcessMonitor.ParentChainTracker;
        PPCT_PROCESS_CHAIN pctChain = NULL;

        NTSTATUS pctStatus = PctBuildChain(pctTracker, ProcessId, &pctChain);
        if (NT_SUCCESS(pctStatus) && pctChain != NULL) {
            //
            // Suspicious ancestry pattern detected â€” report to BehaviorEngine
            //
            if (pctChain->HasSuspiciousAncestor && pctChain->SuspicionScore > 0) {
                BeEngineSubmitEvent(
                    BehaviorEvent_SuspiciousParentChild,
                    BehaviorCategory_ProcessExecution,
                    HandleToULong(ProcessId),
                    &pctChain->SuspicionScore,
                    sizeof(ULONG),
                    min(pctChain->SuspicionScore / 10, 80),
                    FALSE,
                    NULL
                );
            }

            //
            // PPID spoofing detected via creation time analysis (independent of
            // the PnpDetectPpidSpoofing check above, which uses creating thread)
            //
            if (pctChain->IsParentSpoofed) {
                BeEngineSubmitEvent(
                    BehaviorEvent_SuspiciousParentChild,
                    BehaviorCategory_DefenseEvasion,
                    HandleToULong(ProcessId),
                    &pctChain->SuspicionScore,
                    sizeof(ULONG),
                    75,
                    FALSE,
                    NULL
                );

                //
                // Augment the flag if PnpDetectPpidSpoofing didn't catch it
                //
                if (!ProcessContext->IsPpidSpoofed) {
                    ProcessContext->IsPpidSpoofed = TRUE;
                    ProcessContext->Flags |= PN_PROC_FLAG_PPID_SPOOFED;
                    InterlockedIncrement64(&g_ProcessMonitor.Stats.PpidSpoofingDetected);
                }
            }

            //
            // Feed chain suspicion score to centralized threat scoring
            //
            if (pctChain->SuspicionScore > 100 && g_ProcessMonitor.ThreatScoringEngine != NULL) {
                TsAddFactor(
                    g_ProcessMonitor.ThreatScoringEngine,
                    ProcessId,
                    TsFactor_Behavioral,
                    "ParentChain-SuspiciousAncestry",
                    (ULONG)(pctChain->SuspicionScore / 10),
                    "Suspicious process ancestry chain detected"
                );
            }

            PctFreeChain(pctChain);
        }
    }

    //
    // Check session isolation
    //
    if (!PnpCheckParentSessionMatch(ProcessContext)) {
        ProcessContext->Flags |= PN_PROC_FLAG_CROSS_SESSION;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.CrossSessionCreations);

        //
        // Feed cross-session creation factor to threat scoring
        // Score: 15 - Moderate indicator, can be legitimate (services)
        //
        if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Context,
                "CrossSessionCreation",
                15,
                "Process created across session boundary"
                );
        }
    }

    //
    // Track elevated processes
    //
    if (ProcessContext->IsElevated) {
        ProcessContext->Flags |= PN_PROC_FLAG_ELEVATED;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ElevatedProcesses);

        //
        // Feed elevation context factor - not inherently malicious but contextually relevant
        // Score: 5 - Low base score, increases suspicion when combined with other factors
        //
        if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Context,
                "ElevatedProcess",
                5,
                "Process running with elevated privileges"
                );
        }
    }

    if (ProcessContext->IsSystem) {
        ProcessContext->Flags |= PN_PROC_FLAG_SYSTEM;
    }

    if (ProcessContext->IsService) {
        ProcessContext->Flags |= PN_PROC_FLAG_SERVICE;
    }

    //
    // Track dangerous privileges - these are high-value indicators
    //
    if (ProcessContext->HasDebugPrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_DEBUG_PRIV;

        //
        // SeDebugPrivilege is a high-value target for attackers (MITRE T1134)
        // Score: 20 - Significant indicator unless process is known system component
        //
        if (g_ProcessMonitor.ThreatScoringEngine != NULL && !ProcessContext->IsSystem) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Behavioral,
                "SeDebugPrivilege",
                20,
                "Process has SeDebugPrivilege - can access other process memory"
                );
        }
    }
    if (ProcessContext->HasImpersonatePrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_IMPERSONATE;

        //
        // SeImpersonatePrivilege enables token manipulation (MITRE T1134)
        //
        if (g_ProcessMonitor.ThreatScoringEngine != NULL && !ProcessContext->IsSystem && !ProcessContext->IsService) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Behavioral,
                "SeImpersonatePrivilege",
                15,
                "Process has SeImpersonatePrivilege - can impersonate other security contexts"
                );
        }
    }
    if (ProcessContext->HasTcbPrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_TCB;

        //
        // SeTcbPrivilege is extremely powerful - should only be held by LSASS
        //
        if (g_ProcessMonitor.ThreatScoringEngine != NULL && !ProcessContext->IsSystem) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Behavioral,
                "SeTcbPrivilege",
                30,
                "Process has SeTcbPrivilege - can act as part of TCB"
                );
        }
    }
    if (ProcessContext->HasAssignPrimaryTokenPrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_ASSIGN_TOKEN;
    }

    //
    // Verify image signature if enabled
    //
    if (g_ProcessMonitor.Config.EnableSignatureVerification) {
        Status = PnpVerifyImageSignature(ProcessContext);
        if (NT_SUCCESS(Status) && ProcessContext->IsSignatureValid) {
            ProcessContext->Flags |= PN_PROC_FLAG_SIGNATURE_VALID;

            //
            // Valid signature provides trust reduction (negative score)
            //
            if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                TsAddFactor(
                    g_ProcessMonitor.ThreatScoringEngine,
                    ProcessId,
                    TsFactor_Reputation,
                    "ValidSignature",
                    -10,
                    "Process image has valid code signature"
                    );
            }
        } else {
            //
            // Unsigned binary in enterprise environment is suspicious
            //
            if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                TsAddFactor(
                    g_ProcessMonitor.ThreatScoringEngine,
                    ProcessId,
                    TsFactor_Reputation,
                    "UnsignedBinary",
                    10,
                    "Process image lacks valid code signature"
                    );
            }
        }
    }

    //
    // Run full analysis
    //
    Status = PnpAnalyzeProcess(ProcessContext);
    if (NT_SUCCESS(Status)) {
        ProcessContext->Flags |= PN_PROC_FLAG_ANALYZED;
    }

    //
    // Deep Process Analysis via ProcessAnalyzer â€” PE header inspection,
    // entropy-based packing detection, security mitigation verification,
    // LOLBin classification, and unified suspicion scoring.
    // Complements the shallow PnpAnalyzeProcess with PE-level forensics.
    //
    if (g_ProcessMonitor.ProcessAnalyzer != NULL) {
        PPA_ANALYZER paAnalyzer = (PPA_ANALYZER)g_ProcessMonitor.ProcessAnalyzer;
        PPA_ANALYSIS_RESULT paResult = NULL;

        NTSTATUS paStatus = PaAnalyzeProcess(paAnalyzer, ProcessId, &paResult);
        if (NT_SUCCESS(paStatus) && paResult != NULL) {
            //
            // Packed PE detection â†’ BehaviorEngine (T1027.002 Software Packing)
            //
            if (paResult->PE.IsPacked) {
                BeEngineSubmitEvent(
                    BehaviorEvent_ProcessMasquerading,
                    BehaviorCategory_DefenseEvasion,
                    HandleToULong(ProcessId),
                    &paResult->PE.Entropy,
                    sizeof(ULONG),
                    35,
                    FALSE,
                    NULL
                    );

                if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                    TsAddFactor(
                        g_ProcessMonitor.ThreatScoringEngine,
                        ProcessId,
                        TsFactor_MITRE,
                        "T1027.002-SoftwarePacking",
                        30,
                        "PE entropy indicates packed/encrypted executable"
                        );
                }
            }

            //
            // Unsigned binary without DEP â†’ high exploitation risk
            //
            if (!paResult->PE.IsSigned && !paResult->Security.HasDEP) {
                if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                    TsAddFactor(
                        g_ProcessMonitor.ThreatScoringEngine,
                        ProcessId,
                        TsFactor_Reputation,
                        "UnsignedNoDEP",
                        20,
                        "Unsigned binary without DEP - high exploitation risk"
                        );
                }
            }

            //
            // Missing critical mitigations (no ASLR + no CFG)
            //
            if (!paResult->Security.HasASLR && !paResult->Security.HasCFG) {
                if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                    TsAddFactor(
                        g_ProcessMonitor.ThreatScoringEngine,
                        ProcessId,
                        TsFactor_Context,
                        "MissingMitigations-ASLR-CFG",
                        15,
                        "Process lacks ASLR and CFG - vulnerable to exploitation"
                        );
                }
            }

            //
            // LOLBin detection from deep analysis
            //
            if (paResult->BehaviorFlags & PA_BEHAVIOR_LOL_BINARY) {
                BeEngineSubmitEvent(
                    BehaviorEvent_LOLBinExecution,
                    BehaviorCategory_ProcessExecution,
                    HandleToULong(ProcessId),
                    &paResult->SuspicionScore,
                    sizeof(ULONG),
                    min(paResult->SuspicionScore, 60),
                    FALSE,
                    NULL
                    );
            }

            //
            // High suspicion from deep analysis â†’ behavioral event
            //
            if (paResult->SuspicionScore >= PA_SUSPICION_THRESHOLD_HIGH) {
                BeEngineSubmitEvent(
                    BehaviorEvent_ProcessCreate,
                    BehaviorCategory_ProcessExecution,
                    HandleToULong(ProcessId),
                    &paResult->SuspicionScore,
                    sizeof(ULONG),
                    min(paResult->SuspicionScore, 80),
                    FALSE,
                    NULL
                    );
            }

            PaFreeAnalysis(paAnalyzer, &paResult);
        }
    }

    //
    // Feed analysis-derived factors to centralized threat scoring
    // These are extracted from PnpAnalyzeProcess results
    //
    if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
        //
        // LOLBin detection (MITRE T1218 - System Binary Proxy Execution)
        //
        if (ProcessContext->Flags & PN_PROC_FLAG_LOLBIN) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_MITRE,
                "T1218-LOLBin",
                15,
                "Living-off-the-land binary detected"
                );
        }

        //
        // Encoded command detection (MITRE T1059 - Command and Scripting Interpreter)
        //
        if (ProcessContext->Flags & PN_PROC_FLAG_ENCODED_CMD) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_MITRE,
                "T1059-EncodedCommand",
                25,
                "Base64/encoded command line detected"
                );
        }

        //
        // Behavioral indicators from command line analysis
        //
        if (ProcessContext->BehaviorFlags & PN_BEHAVIOR_SUSPICIOUS_PS) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Behavioral,
                "SuspiciousPowerShell",
                15,
                "Suspicious PowerShell flags detected (-nop, -w hidden, bypass)"
                );
        }

        if (ProcessContext->BehaviorFlags & PN_BEHAVIOR_DOWNLOAD_CRADLE) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Behavioral,
                "DownloadCradle",
                20,
                "Download cradle pattern detected in command line"
                );
        }

        if (ProcessContext->BehaviorFlags & PN_BEHAVIOR_REFLECTION_LOAD) {
            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_Behavioral,
                "ReflectionLoad",
                25,
                "Reflective loading pattern detected"
                );
        }
    }

    //
    // WSL/Container escape detection â€” classify WSL processes and detect
    // host escape attempts (MITRE T1611)
    //
    WslMonCheckProcessCreate(
        ProcessId,
        CreateInfo->ParentProcessId,
        CreateInfo->ImageFileName
        );

    //
    // Clipboard abuse detection â€” detect clipboard data theft patterns (T1115).
    // Score graduates based on indicator combination: encoded commands + known
    // stealer image warrants a higher score than a simple clipboard command line.
    //
    {
        ULONG cbIndicators = CbMonCheckProcessCreate(ProcessId, CreateInfo);
        if (cbIndicators != 0 && g_ProcessMonitor.ThreatScoringEngine != NULL) {
            UINT32 cbScore = 15;

            if (cbIndicators & CbIndicator_KnownStealerImage) {
                cbScore += 25;
            }
            if (cbIndicators & CbIndicator_EncodedClipboardCmd) {
                cbScore += 20;
            }

            TsAddFactor(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                TsFactor_MITRE,
                "T1115-ClipboardAbuse",
                cbScore,
                "Clipboard data access/theft indicators detected"
                );
        }
    }

    //
    // Application Control â€” enforce allowlist/blocklist policy.
    // In Enforce mode this can block process creation (MITRE M1038).
    // Note: ImageHash is NULL here because SHA-256 computation happens
    // asynchronously in the scan pipeline (ScanBridge â†’ user-mode).
    // Hash-based rules activate when scan results flow back via CommPort.
    //
    {
        AC_VERDICT AcVerdict = AcCheckProcessExecution(
            CreateInfo->ImageFileName,
            NULL,
            ProcessId,
            CreateInfo->ParentProcessId
            );
        if (AcVerdict == AcVerdict_Block && CreateInfo != NULL) {
            ShouldBlock = TRUE;
        }
    }

    //
    // Calculate local suspicion score (legacy compatibility)
    // Use max of flag-based score and accumulated sub-analyzer score
    // (CLP, EM, HT already boosted Context->SuspicionScore in PnpAnalyzeProcess)
    //
    SuspicionScore = PnpCalculateSuspicionScore(ProcessContext);
    if (ProcessContext->SuspicionScore > SuspicionScore) {
        SuspicionScore = ProcessContext->SuspicionScore;
    }
    ProcessContext->SuspicionScore = SuspicionScore;

    if (SuspicionScore >= PN_SUSPICION_MEDIUM) {
        ProcessContext->Flags |= PN_PROC_FLAG_SUSPICIOUS;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.SuspiciousProcesses);
    }

    //
    // Submit process creation event to BehaviorEngine for kill-chain correlation.
    // BehaviorEngine internally drives AttackChainTracker â†’ MITREMapper pipeline.
    // We submit at PASSIVE_LEVEL after all analysis enrichment is complete.
    //
    // Enhance the suspicion score with ThreatScoring engine's aggregated
    // per-process risk assessment (reputation, IoC matches, behavioral factors).
    //
    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
        BEHAVIOR_RESPONSE_ACTION beResponse = BehaviorResponse_Allow;
        UINT32 finalThreatScore = SuspicionScore;

        PTS_SCORING_ENGINE tsEngine = g_ProcessMonitor.ThreatScoringEngine;
        if (tsEngine != NULL) {
            PTS_THREAT_SCORE tsResult = (PTS_THREAT_SCORE)ExAllocatePool2(
                POOL_FLAG_PAGED, sizeof(TS_THREAT_SCORE), 'sTsS');
            if (tsResult != NULL) {
                RtlZeroMemory(tsResult, sizeof(TS_THREAT_SCORE));
                NTSTATUS tsStatus = TsCalculateScoreInPlace(tsEngine, ProcessId, tsResult);
                if (NT_SUCCESS(tsStatus) && tsResult->NormalizedScore > finalThreatScore) {
                    finalThreatScore = tsResult->NormalizedScore;
                }
                ExFreePoolWithTag(tsResult, 'sTsS');
            }
        }

        NTSTATUS beStatus = BeEngineSubmitEvent(
            BehaviorEvent_ProcessCreate,
            BehaviorCategory_ProcessExecution,
            HandleToULong(ProcessId),
            ProcessContext,
            sizeof(*ProcessContext),
            finalThreatScore,
            g_ProcessMonitor.Config.BlockSuspiciousProcesses,
            &beResponse
            );

        if (NT_SUCCESS(beStatus) && beResponse == BehaviorResponse_Block) {
            ShouldBlock = TRUE;
        }
    }

    //
    // Submit targeted behavioral events for specific high-confidence detections
    //
    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
        if (ProcessContext->IsPpidSpoofed) {
            BeEngineSubmitEvent(
                BehaviorEvent_SuspiciousParentChild,
                BehaviorCategory_DefenseEvasion,
                HandleToULong(ProcessId),
                NULL, 0,
                40,
                FALSE,
                NULL
                );
        }
        if (ProcessContext->Flags & PN_PROC_FLAG_ENCODED_CMD) {
            BeEngineSubmitEvent(
                BehaviorEvent_ScriptExecution,
                BehaviorCategory_ProcessExecution,
                HandleToULong(ProcessId),
                NULL, 0,
                30,
                FALSE,
                NULL
                );
        }
        if (ProcessContext->IsElevated && !ProcessContext->IsSystem) {
            BeEngineSubmitEvent(
                BehaviorEvent_ElevationOfPrivilege,
                BehaviorCategory_PrivilegeOperation,
                HandleToULong(ProcessId),
                NULL, 0,
                15,
                FALSE,
                NULL
                );
        }
    }

    //
    // Creation-time process hollowing / ghosting / doppelganging detection.
    // PhAnalyzeAtCreation inspects the new process's PEB and in-memory image
    // against the on-disk file BEFORE the process has a chance to execute.
    // The callback registered via PhRegisterCallback (MmpHollowingDetectionCallback)
    // routes confirmed detections to BehaviorEngine automatically.
    //
    {
        PPH_DETECTOR HollowDetector = MmMonitorGetHollowingDetector();
        if (HollowDetector != NULL && !ProcessContext->IsSystem) {
            PPH_ANALYSIS_RESULT HollowResult = NULL;
            NTSTATUS HollowStatus = PhAnalyzeAtCreation(
                HollowDetector,
                ProcessId,
                CreateInfo->ParentProcessId,
                Process,
                &HollowResult
                );

            if (NT_SUCCESS(HollowStatus) && HollowResult != NULL) {
                if (HollowResult->HollowingDetected) {
                    ProcessContext->Flags |= PN_PROC_FLAG_HOLLOWED;

                    //
                    // Contribute to threat scoring â€” hollowed process is strong indicator
                    //
                    if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
                        TsAddFactor(
                            g_ProcessMonitor.ThreatScoringEngine,
                            ProcessId,
                            TsFactor_MITRE,
                            "T1055.012-ProcessHollowing",
                            (ULONG)min(HollowResult->ConfidenceScore, 100),
                            "Process hollowing detected at creation time"
                            );
                    }

                    SuspicionScore += (ULONG)min(HollowResult->ConfidenceScore, 100);
                    ProcessContext->SuspicionScore = SuspicionScore;

                    DbgPrintEx(
                        DPFLTR_IHVDRIVER_ID,
                        DPFLTR_WARNING_LEVEL,
                        "[ShadowStrike/ProcessNotify] HOLLOWING DETECTED at creation: "
                        "PID=%lu, Type=%u, Confidence=%u\n",
                        HandleToULong(ProcessId),
                        HollowResult->Type,
                        HollowResult->ConfidenceScore
                        );
                }

                PhFreeResult(HollowResult);
            }
        }
    }

    //
    // Query centralized threat scoring engine for authoritative verdict
    // This aggregates all factors with proper weighting, decay, and thresholds
    //
    {
        TS_VERDICT TsVerdict = TsVerdict_Unknown;
        ULONG TsNormalizedScore = 0;

        if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
            Status = TsGetVerdict(
                g_ProcessMonitor.ThreatScoringEngine,
                ProcessId,
                &TsVerdict,
                &TsNormalizedScore
                );

            if (NT_SUCCESS(Status)) {
                //
                // Use centralized verdict for blocking decisions
                // TsVerdict_Blocked indicates score >= BlockedThreshold (95)
                //
                if (TsVerdict == TsVerdict_Blocked) {
                    ShouldBlock = TRUE;

                    DbgPrintEx(
                        DPFLTR_IHVDRIVER_ID,
                        DPFLTR_WARNING_LEVEL,
                        "[ShadowStrike/ProcessNotify] ThreatScoring BLOCKED verdict: "
                        "PID=%lu, NormalizedScore=%lu\n",
                        HandleToULong(ProcessId),
                        TsNormalizedScore
                        );
                } else if (TsVerdict == TsVerdict_Malicious) {
                    //
                    // Malicious verdict - block if blocking is enabled
                    //
                    if (g_ProcessMonitor.Config.BlockSuspiciousProcesses) {
                        ShouldBlock = TRUE;
                    }
                }

                //
                // Sync local score with centralized score for reporting
                //
                if (TsNormalizedScore > SuspicionScore) {
                    SuspicionScore = TsNormalizedScore;
                    ProcessContext->SuspicionScore = SuspicionScore;
                }
            }
        }
    }

    //
    // Legacy blocking check (fallback if ThreatScoring unavailable)
    //
    if (!ShouldBlock &&
        g_ProcessMonitor.Config.BlockSuspiciousProcesses &&
        SuspicionScore >= g_ProcessMonitor.Config.MinBlockScore) {
        ShouldBlock = TRUE;
    }

    //
    // Check if process is trusted (override block)
    //
    if (ShouldBlock && PnpIsTrustedProcess(ProcessContext)) {
        ShouldBlock = FALSE;
        ProcessContext->Flags |= PN_PROC_FLAG_TRUSTED;
    }

    //
    // Insert context into tracking structures
    //
    Status = PnpInsertProcessContext(ProcessContext);
    if (!NT_SUCCESS(Status)) {
        //
        // Failed to insert - will be freed in cleanup
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] Failed to insert context for PID %lu: 0x%08X\n",
            HandleToULong(ProcessId),
            Status
            );
        goto Cleanup;
    }

    //
    // Add process to relationship graph for cross-process activity tracking.
    // Enables injection chain detection, suspicious cluster analysis, and
    // parent-child graph correlation (MITRE T1055, T1134).
    //
    {
        PPR_GRAPH prGraph = PaGetProcessRelationshipGraph();
        if (prGraph != NULL) {
            (VOID)PrAddProcess(
                prGraph,
                ProcessId,
                CreateInfo->ParentProcessId,
                (PUNICODE_STRING)CreateInfo->ImageFileName
                );
        }
    }

    //
    // Send notification to user-mode
    //
    Status = PnpSendProcessNotification(ProcessContext, TRUE, CreateInfo);
    if (!NT_SUCCESS(Status) && Status != STATUS_PORT_DISCONNECTED) {
        //
        // Check if user-mode requested block
        //
        if (Status == STATUS_ACCESS_DENIED) {
            ShouldBlock = TRUE;
        }
    }

    //
    // Also send through ScanBridge for telemetry statistics consistency.
    // Thread/Image/Registry all go through ScanBridge; process creation
    // should too for circuit breaker and stats tracking (fire-and-forget).
    //
    ShadowStrikeSendProcessEvent(
        ProcessContext->ProcessId,
        ProcessContext->ParentProcessId,
        TRUE,
        &ProcessContext->ImagePath,
        &ProcessContext->CommandLine
    );

    //
    // Stream process creation event to high-performance telemetry buffer.
    // TelemetryBuffer provides per-CPU ring buffer delivery to user-mode
    // at < 100ns latency â€” complementary to CommPort synchronous path.
    //
    {
        PTB_MANAGER tbMgr = ShadowStrikeGetTelemetryBuffer();
        if (tbMgr != NULL) {
            struct {
                ULONG ProcessId;
                ULONG ParentProcessId;
                ULONG SessionId;
                ULONG Flags;
            } tbPayload;
            tbPayload.ProcessId = HandleToULong(ProcessContext->ProcessId);
            tbPayload.ParentProcessId = HandleToULong(ProcessContext->ParentProcessId);
            tbPayload.SessionId = ProcessContext->SessionId;
            tbPayload.Flags = ProcessContext->Flags;
            TbEnqueue(tbMgr, TbEntryType_ProcessCreate,
                      &tbPayload, sizeof(tbPayload), NULL);
        }
    }

    //
    // Apply blocking decision
    // CRITICAL: Verify CreateInfo is not NULL before dereferencing
    //
    if (ShouldBlock && CreateInfo != NULL) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        ProcessContext->Flags |= PN_PROC_FLAG_BLOCKED;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessesBlocked);
        SHADOWSTRIKE_INC_STAT(ProcessesBlocked);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] BLOCKED process creation: PID=%lu, Score=%lu, Flags=0x%08X\n",
            HandleToULong(ProcessId),
            SuspicionScore,
            ProcessContext->Flags
            );

        //
        // Emit ETW telemetry for blocked process (CRITICAL security event â€” never throttled)
        //
        TeLogProcessBlocked(
            HandleToULong(ProcessId),
            HandleToULong(ProcessContext->ParentProcessId),
            &ProcessContext->ImagePath,
            SuspicionScore,
            L"Behavioral analysis block"
        );
    } else {
        //
        // Emit ETW telemetry for process creation (informational)
        //
        TeLogProcessCreate(
            HandleToULong(ProcessId),
            HandleToULong(ProcessContext->ParentProcessId),
            &ProcessContext->ImagePath,
            &ProcessContext->CommandLine,
            SuspicionScore,
            ProcessContext->Flags
        );
    }

    //
    // Release caller's reference â€” the tracking list holds its own ref
    // (taken by PnpInsertProcessContext). Without this deref, every
    // context leaks with RefCount stuck at 1, leaking the EPROCESS
    // reference and pool memory until PoolTracker hits 4MB â†’ self-DoS.
    //
    PnpDereferenceContext(ProcessContext);
    ProcessContext = NULL;

Cleanup:
    if (ProcessContext != NULL) {
        PnpFreeProcessContext(ProcessContext);
    }

    SSPM_LATENCY_END(ShadowStrikeGetPerformanceMonitor(),
                     SsPmMetric_CallbackLatencyUs, proc);
    SHADOWSTRIKE_RELEASE_RUNDOWN();
}


// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

static PPN_PROCESS_CONTEXT
PnpAllocateProcessContext(
    VOID
    )
{
    PPN_PROCESS_CONTEXT Context;

    //
    // Check pool limits before allocation
    //
    if (!PnpCheckPoolLimit(sizeof(PN_PROCESS_CONTEXT))) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.PoolLimitDrops);
        return NULL;
    }

    Context = (PPN_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_ProcessMonitor.ContextLookaside
        );

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(PN_PROCESS_CONTEXT));
        Context->RefCount = 1;
        InitializeListHead(&Context->ListEntry);
        InitializeListHead(&Context->HashEntry);
        Context->InsertedInList = FALSE;
        Context->InsertedInHash = FALSE;

        PnpTrackPoolAllocation(sizeof(PN_PROCESS_CONTEXT));
    }

    return Context;
}


static VOID
PnpFreeProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // Verify context is not still in lists
    //
    NT_ASSERT(!Context->InsertedInList);
    NT_ASSERT(!Context->InsertedInHash);

    //
    // Free allocated strings
    //
    if (Context->ImagePath.Buffer != NULL) {
        PnpTrackPoolFree(Context->ImagePath.MaximumLength);
        ShadowStrikeFreePoolWithTag(Context->ImagePath.Buffer, PN_POOL_TAG);
        Context->ImagePath.Buffer = NULL;
    }

    if (Context->CommandLine.Buffer != NULL) {
        PnpTrackPoolFree(Context->CommandLine.MaximumLength);
        ShadowStrikeFreePoolWithTag(Context->CommandLine.Buffer, PN_POOL_TAG);
        Context->CommandLine.Buffer = NULL;
    }

    if (Context->ImageFileName.Buffer != NULL) {
        PnpTrackPoolFree(Context->ImageFileName.MaximumLength);
        ShadowStrikeFreePoolWithTag(Context->ImageFileName.Buffer, PN_POOL_TAG);
        Context->ImageFileName.Buffer = NULL;
    }

    //
    // Dereference process object if held
    //
    if (Context->ProcessObject != NULL) {
        ObDereferenceObject(Context->ProcessObject);
        Context->ProcessObject = NULL;
    }

    PnpTrackPoolFree(sizeof(PN_PROCESS_CONTEXT));
    ExFreeToNPagedLookasideList(&g_ProcessMonitor.ContextLookaside, Context);
}


static ULONG
PnpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    //
    // MurmurHash3-style mixing for good distribution
    //
    Value = Value ^ (Value >> 16);
    Value = Value * 0x85EBCA6B;
    Value = Value ^ (Value >> 13);
    Value = Value * 0xC2B2AE35;
    Value = Value ^ (Value >> 16);

    return (ULONG)(Value % PN_HASH_BUCKET_COUNT);
}


static PPN_PROCESS_CONTEXT
PnpLookupProcessContext(
    _In_ HANDLE ProcessId
    )
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;
    PLIST_ENTRY Entry;
    PPN_PROCESS_CONTEXT Context = NULL;
    PPN_PROCESS_CONTEXT FoundContext = NULL;

    BucketIndex = PnpHashProcessId(ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Bucket->Lock);

    for (Entry = Bucket->List.Flink;
         Entry != &Bucket->List;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, HashEntry);

        if (Context->ProcessId == ProcessId) {
            //
            // Found - take reference before releasing lock
            //
            PnpReferenceContext(Context);
            FoundContext = Context;
            break;
        }
    }

    ExReleasePushLockShared(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return FoundContext;
}


static NTSTATUS
PnpInsertProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Inserts a process context into tracking structures.

    Lock ordering: ProcessListLock THEN Bucket->Lock

Arguments:
    Context - The context to insert.

Return Value:
    STATUS_SUCCESS or error code.
--*/
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;

    //
    // Verify context is not already inserted
    //
    if (InterlockedCompareExchange(&Context->InsertedInList, FALSE, FALSE) ||
        InterlockedCompareExchange(&Context->InsertedInHash, FALSE, FALSE)) {
        NT_ASSERT(FALSE);
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Check max context limit
    //
    if (InterlockedCompareExchange(&g_ProcessMonitor.ProcessCount, 0, 0) >=
        PN_MAX_PROCESS_CONTEXTS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Reference for list storage
    //
    PnpReferenceContext(Context);

    //
    // Lock ordering: ProcessListLock first, then bucket lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    //
    // Insert into main list
    //
    InsertTailList(&g_ProcessMonitor.ProcessList, &Context->ListEntry);
    InterlockedExchange(&Context->InsertedInList, TRUE);
    InterlockedIncrement(&g_ProcessMonitor.ProcessCount);

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Insert into hash table
    //
    BucketIndex = PnpHashProcessId(Context->ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    InsertTailList(&Bucket->List, &Context->HashEntry);
    InterlockedExchange(&Context->InsertedInHash, TRUE);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


static VOID
PnpRemoveProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Removes a process context from tracking structures.

    Lock ordering: ProcessListLock THEN Bucket->Lock
--*/
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;
    BOOLEAN WasInList = FALSE;
    BOOLEAN WasInHash = FALSE;

    //
    // Lock ordering: ProcessListLock first
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    if (InterlockedCompareExchange(&Context->InsertedInList, FALSE, TRUE)) {
        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_ProcessMonitor.ProcessCount);
            WasInList = TRUE;
        }
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Then bucket lock
    //
    BucketIndex = PnpHashProcessId(Context->ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    if (InterlockedCompareExchange(&Context->InsertedInHash, FALSE, TRUE)) {
        if (!IsListEmpty(&Context->HashEntry)) {
            RemoveEntryList(&Context->HashEntry);
            InitializeListHead(&Context->HashEntry);
            WasInHash = TRUE;
        }
    }

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Release list reference if was inserted
    //
    if (WasInList || WasInHash) {
        PnpDereferenceContext(Context);
    }
}


static VOID
PnpReferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
{
    LONG NewCount = InterlockedIncrement(&Context->RefCount);
    NT_ASSERT(NewCount > 1);
    UNREFERENCED_PARAMETER(NewCount);
}


static VOID
PnpDereferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
{
    LONG NewCount = InterlockedDecrement(&Context->RefCount);
    NT_ASSERT(NewCount >= 0);

    if (NewCount == 0) {
        PnpFreeProcessContext(Context);
    }
}


// ============================================================================
// PROCESS INFORMATION CAPTURE
// ============================================================================

static NTSTATUS
PnpCaptureProcessInfo(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PPN_PROCESS_CONTEXT Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWCHAR Buffer = NULL;
    SIZE_T SafeBufferSize;

    //
    // Basic identification
    //
    Context->ProcessId = ProcessId;
    Context->ParentProcessId = CreateInfo->ParentProcessId;
    Context->CreatingProcessId = CreateInfo->CreatingThreadId.UniqueProcess;
    Context->CreatingThreadId = CreateInfo->CreatingThreadId.UniqueThread;

    //
    // Store creating process ID as potential real parent
    //
    Context->RealParentProcessId = CreateInfo->CreatingThreadId.UniqueProcess;

    //
    // Store creating process context in ProcessUtils hash table.
    // This enables anti-parent-spoofing detection (T1134.004) via
    // ShadowStrikeValidateParentChild â€” compares captured creating PID
    // against the (potentially spoofed) InheritedFromUniqueProcessId.
    // Best-effort: failure here is non-fatal (fallback to inherited PID).
    //
    ShadowStrikeStoreCreatingProcessContext(
        ProcessId,
        CreateInfo->CreatingThreadId.UniqueProcess,
        CreateInfo->CreatingThreadId.UniqueThread
    );

    //
    // Timing
    //
    KeQuerySystemTime(&Context->CreateTime);

    //
    // Reference process object
    // Note: We hold this reference for the lifetime of the context
    // This is intentional to prevent process object reuse issues
    //
    Status = ObReferenceObjectByPointer(
        Process,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode
        );
    if (NT_SUCCESS(Status)) {
        Context->ProcessObject = Process;
    }

    //
    // Capture image path with safe size calculation
    //
    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Length > 0 &&
        CreateInfo->ImageFileName->Buffer != NULL) {

        //
        // Validate length and prevent overflow
        //
        if (CreateInfo->ImageFileName->Length <= PN_MAX_IMAGE_PATH_CAPTURE * sizeof(WCHAR)) {

            //
            // Safe size calculation: check for overflow
            //
            SafeBufferSize = (SIZE_T)CreateInfo->ImageFileName->Length + sizeof(WCHAR);
            if (SafeBufferSize > CreateInfo->ImageFileName->Length) {  // Overflow check

                if (PnpCheckPoolLimit(SafeBufferSize)) {
                    Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                        NonPagedPoolNx,
                        SafeBufferSize,
                        PN_POOL_TAG
                        );

                    if (Buffer != NULL) {
                        PnpTrackPoolAllocation(SafeBufferSize);

                        RtlCopyMemory(
                            Buffer,
                            CreateInfo->ImageFileName->Buffer,
                            CreateInfo->ImageFileName->Length
                            );

                        //
                        // ALWAYS null-terminate for safe string operations
                        //
                        Buffer[CreateInfo->ImageFileName->Length / sizeof(WCHAR)] = L'\0';

                        Context->ImagePath.Buffer = Buffer;
                        Context->ImagePath.Length = CreateInfo->ImageFileName->Length;
                        Context->ImagePath.MaximumLength = (USHORT)SafeBufferSize;

                        //
                        // Extract filename using safe search
                        //
                        PWCHAR LastSlash = NULL;
                        PWCHAR Ptr = Buffer;
                        USHORT RemainingChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);

                        while (RemainingChars > 0 && *Ptr != L'\0') {
                            if (*Ptr == L'\\') {
                                LastSlash = Ptr;
                            }
                            Ptr++;
                            RemainingChars--;
                        }

                        if (LastSlash != NULL && (LastSlash + 1) < (Buffer + Context->ImagePath.Length / sizeof(WCHAR))) {
                            PWCHAR FileName = LastSlash + 1;
                            SIZE_T FileNameLen = wcslen(FileName) * sizeof(WCHAR);
                            SIZE_T FileNameBufferSize = FileNameLen + sizeof(WCHAR);

                            if (FileNameLen > 0 && FileNameLen < 512 * sizeof(WCHAR) &&
                                PnpCheckPoolLimit(FileNameBufferSize)) {

                                PWCHAR FileNameBuffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                                    NonPagedPoolNx,
                                    FileNameBufferSize,
                                    PN_POOL_TAG
                                    );

                                if (FileNameBuffer != NULL) {
                                    PnpTrackPoolAllocation(FileNameBufferSize);
                                    RtlCopyMemory(FileNameBuffer, FileName, FileNameLen);
                                    FileNameBuffer[FileNameLen / sizeof(WCHAR)] = L'\0';
                                    Context->ImageFileName.Buffer = FileNameBuffer;
                                    Context->ImageFileName.Length = (USHORT)FileNameLen;
                                    Context->ImageFileName.MaximumLength = (USHORT)FileNameBufferSize;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    //
    // Capture command line with safe size calculation
    //
    if (CreateInfo->CommandLine != NULL &&
        CreateInfo->CommandLine->Length > 0 &&
        CreateInfo->CommandLine->Buffer != NULL) {

        USHORT CaptureLength = CreateInfo->CommandLine->Length;

        //
        // Cap command line length
        //
        if (CaptureLength > PN_MAX_COMMAND_LINE_CAPTURE * sizeof(WCHAR)) {
            CaptureLength = PN_MAX_COMMAND_LINE_CAPTURE * sizeof(WCHAR);
        }

        //
        // Safe size calculation with overflow check
        //
        SafeBufferSize = (SIZE_T)CaptureLength + sizeof(WCHAR);
        if (SafeBufferSize > CaptureLength && PnpCheckPoolLimit(SafeBufferSize)) {

            Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                SafeBufferSize,
                PN_POOL_TAG
                );

            if (Buffer != NULL) {
                PnpTrackPoolAllocation(SafeBufferSize);
                RtlCopyMemory(Buffer, CreateInfo->CommandLine->Buffer, CaptureLength);

                //
                // ALWAYS null-terminate
                //
                Buffer[CaptureLength / sizeof(WCHAR)] = L'\0';

                Context->CommandLine.Buffer = Buffer;
                Context->CommandLine.Length = CaptureLength;
                Context->CommandLine.MaximumLength = (USHORT)SafeBufferSize;
            }
        }
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
PnpCaptureTokenInfo(
    _In_ PEPROCESS Process,
    _Out_ PPN_PROCESS_CONTEXT Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PACCESS_TOKEN Token = NULL;
    ULONG SessionId = 0;

    __try {
        //
        // Get primary token of the TARGET process (not current thread)
        //
        Token = PsReferencePrimaryToken(Process);
        if (Token == NULL) {
            return STATUS_UNSUCCESSFUL;
        }

        //
        // Get session ID
        //
        Status = SeQuerySessionIdToken(Token, &SessionId);
        if (NT_SUCCESS(Status)) {
            Context->SessionId = SessionId;
        }

        //
        // Check for restricted token (typically low integrity)
        //
        if (SeTokenIsRestricted(Token)) {
            Context->IntegrityLevel = 0;  // Low
        }

        //
        // Check for admin token
        //
        if (SeTokenIsAdmin(Token)) {
            Context->IsElevated = TRUE;
        }

        //
        // Check for dangerous privileges in the TARGET process's token
        // Build a subject context from the already-captured primary token
        // so we check the NEW process, not the calling thread's context
        //
        {
            SECURITY_SUBJECT_CONTEXT SubjectContext;
            PRIVILEGE_SET PrivSet;

            RtlZeroMemory(&SubjectContext, sizeof(SubjectContext));
            SubjectContext.PrimaryToken = Token;
            SubjectContext.ClientToken = NULL;
            SubjectContext.ProcessAuditId = (PVOID)Process;

            //
            // SE_DEBUG_PRIVILEGE (20) - Can debug any process
            //
            PrivSet.PrivilegeCount = 1;
            PrivSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
            PrivSet.Privilege[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
            PrivSet.Privilege[0].Attributes = 0;

            if (SePrivilegeCheck(&PrivSet, &SubjectContext, UserMode)) {
                Context->HasDebugPrivilege = TRUE;
            }

            //
            // SE_IMPERSONATE_PRIVILEGE (29) - Can impersonate tokens
            //
            PrivSet.Privilege[0].Luid = RtlConvertLongToLuid(SE_IMPERSONATE_PRIVILEGE);
            PrivSet.Privilege[0].Attributes = 0;

            if (SePrivilegeCheck(&PrivSet, &SubjectContext, UserMode)) {
                Context->HasImpersonatePrivilege = TRUE;
            }

            //
            // SE_TCB_PRIVILEGE (7) - Act as part of OS
            //
            PrivSet.Privilege[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
            PrivSet.Privilege[0].Attributes = 0;

            if (SePrivilegeCheck(&PrivSet, &SubjectContext, UserMode)) {
                Context->HasTcbPrivilege = TRUE;
            }

            //
            // SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3) - Assign process token
            //
            PrivSet.Privilege[0].Luid = RtlConvertLongToLuid(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE);
            PrivSet.Privilege[0].Attributes = 0;

            if (SePrivilegeCheck(&PrivSet, &SubjectContext, UserMode)) {
                Context->HasAssignPrimaryTokenPrivilege = TRUE;
            }

            //
            // SE_LOAD_DRIVER_PRIVILEGE (10) - Load kernel drivers
            //
            PrivSet.Privilege[0].Luid = RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE);
            PrivSet.Privilege[0].Attributes = 0;

            if (SePrivilegeCheck(&PrivSet, &SubjectContext, UserMode)) {
                Context->HasLoadDriverPrivilege = TRUE;
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    //
    // Release token
    //
    if (Token != NULL) {
        PsDereferencePrimaryToken(Token);
    }

    //
    // Get parent session ID for cross-session detection
    //
    if (Context->ParentProcessId != NULL) {
        PEPROCESS ParentProcess = NULL;
        Status = PsLookupProcessByProcessId(Context->ParentProcessId, &ParentProcess);
        if (NT_SUCCESS(Status)) {
            PACCESS_TOKEN ParentToken = PsReferencePrimaryToken(ParentProcess);
            if (ParentToken != NULL) {
                ULONG ParentSessionId = 0;
                if (NT_SUCCESS(SeQuerySessionIdToken(ParentToken, &ParentSessionId))) {
                    Context->ParentSessionId = ParentSessionId;
                }
                PsDereferencePrimaryToken(ParentToken);
            }
            ObDereferenceObject(ParentProcess);
        }
    }

    //
    // Determine if SYSTEM or service process
    // Session 0 + elevated is typically a service
    //
    if (Context->SessionId == 0 && Context->IsElevated) {
        Context->IsService = TRUE;

        //
        // Check for SYSTEM specifically by checking for TCB privilege
        // (Only SYSTEM and very privileged services have this)
        //
        if (Context->HasTcbPrivilege) {
            Context->IsSystem = TRUE;
        }
    }

    return STATUS_SUCCESS;
}


// ============================================================================
// PPID SPOOFING DETECTION
// ============================================================================

static BOOLEAN
PnpDetectPpidSpoofing(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
/*++
Routine Description:
    Detects Parent Process ID (PPID) spoofing.

    PPID spoofing occurs when an attacker uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    to make a process appear to have a different parent than the actual creator.

    Detection: Compare CreateInfo->ParentProcessId with CreatingThreadId.UniqueProcess
--*/
{
    UNREFERENCED_PARAMETER(CreateInfo);

    //
    // The creating process (from CreatingThreadId) should normally be the parent
    // If they differ, the parent was explicitly set to a different process
    //
    if (Context->ParentProcessId != Context->CreatingProcessId) {
        //
        // ParentProcessId was spoofed to a different value
        //

        //
        // Exception: Some legitimate scenarios like AppInfo service elevation
        // Check if creating process is a known system process
        //
        if (PnpIsKnownSystemProcess(Context->CreatingProcessId, NULL)) {
            //
            // System process creating with different parent is often legitimate
            // (e.g., services.exe, svchost.exe doing elevation)
            //
            return FALSE;
        }

        //
        // Exception: Self-parenting (process setting itself as parent)
        // This is sometimes done for orphaning - VERY suspicious
        //
        if (Context->ParentProcessId == Context->ProcessId) {
            return TRUE;  // Definitely suspicious
        }

        //
        // Exception: Parent is System (PID 4) or Idle (PID 0)
        // Usually legitimate for services
        //
        if (HandleToULong(Context->ParentProcessId) <= 4) {
            //
            // Check if creator is also low PID
            //
            if (HandleToULong(Context->CreatingProcessId) > 4) {
                return TRUE;  // Spoofed to appear as system child
            }
            return FALSE;
        }

        //
        // Generic case: Parent differs from creator
        //
        return TRUE;
    }

    return FALSE;
}


// ============================================================================
// PROCESS ANALYSIS
// ============================================================================

static NTSTATUS
PnpAnalyzeProcess(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Performs comprehensive process analysis including:
    - Command line pattern matching (case-insensitive)
    - LOLBin detection
    - Encoded command detection
    - Behavioral indicators
--*/
{
    //
    // Command line analysis
    //
    if (g_ProcessMonitor.Config.EnableCommandLineAnalysis &&
        Context->CommandLine.Buffer != NULL &&
        Context->CommandLine.Length > 0) {

        PWCHAR CmdLine = Context->CommandLine.Buffer;
        USHORT CmdLenBytes = Context->CommandLine.Length;
        SIZE_T CmdLenChars = CmdLenBytes / sizeof(WCHAR);

        //
        // Pattern: PowerShell encoded command (-enc, -e, -encodedcommand)
        // Use case-insensitive matching
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-enc") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-EncodedCommand") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-e ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-ec ")) {

            Context->Flags |= PN_PROC_FLAG_ENCODED_CMD;
            Context->BehaviorFlags |= PN_BEHAVIOR_BASE64_ENCODED;
            InterlockedIncrement64(&g_ProcessMonitor.Stats.EncodedCommands);
        }

        //
        // Pattern: PowerShell bypass flags
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-nop") ||      // NoProfile
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-noni") ||     // NonInteractive
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-w hidden") || // WindowStyle Hidden
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-windowstyle hidden") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-ep bypass") || // ExecutionPolicy Bypass
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-executionpolicy bypass") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"bypass")) {

            Context->BehaviorFlags |= PN_BEHAVIOR_SUSPICIOUS_PS;
        }

        //
        // Pattern: Download cradle indicators
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"DownloadString") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"DownloadFile") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"DownloadData") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"WebClient") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Invoke-WebRequest") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Invoke-RestMethod") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"wget ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"curl ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"bitsadmin") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Start-BitsTransfer")) {

            Context->BehaviorFlags |= PN_BEHAVIOR_DOWNLOAD_CRADLE;
        }

        //
        // Pattern: Reflection/memory loading (fileless)
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"[Reflection.Assembly]") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Reflection.Assembly") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"::Load(") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"FromBase64String")) {

            Context->BehaviorFlags |= PN_BEHAVIOR_REFLECTION_LOAD;
        }

        //
        // Pattern: Suspicious cmd.exe usage
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"/c ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"/k ")) {

            //
            // Check for chained commands or suspicious patterns
            //
            if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"&&") ||
                PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"| ") ||
                PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"^")) {

                Context->BehaviorFlags |= PN_BEHAVIOR_SUSPICIOUS_CMD;
            }
        }

        //
        // Check command line length (very long = suspicious)
        //
        if (CmdLenChars > 2048) {
            Context->BehaviorFlags |= PN_BEHAVIOR_LONG_CMDLINE;
        }

        //
        // Deep command-line analysis via CommandLineParser.
        // CLP provides: LOLBin DB lookup, Base64 decoding, obfuscation scoring,
        // download cradle detection, execution bypass detection, combo scoring.
        // Results are merged into existing PN flags and forwarded to BehaviorEngine.
        //
        {
            PCLP_PARSER ClpParser = PaGetCommandLineParser();
            if (ClpParser != NULL) {
                PCLP_PARSED_COMMAND ClpParsed = NULL;
                NTSTATUS ClpStatus;

                ClpStatus = ClpParse(ClpParser, &Context->CommandLine, &ClpParsed);
                if (NT_SUCCESS(ClpStatus) && ClpParsed != NULL) {
                    CLP_SUSPICION ClpFlags = ClpSuspicion_None;
                    ULONG ClpScore = 0;

                    ClpStatus = ClpAnalyze(ClpParser, ClpParsed, &ClpFlags, &ClpScore);
                    if (NT_SUCCESS(ClpStatus) && ClpScore > 0) {
                        //
                        // Map CLP suspicion flags to PN behavioral flags
                        //
                        if (ClpFlags & ClpSuspicion_EncodedCommand) {
                            Context->Flags |= PN_PROC_FLAG_ENCODED_CMD;
                            Context->BehaviorFlags |= PN_BEHAVIOR_BASE64_ENCODED;
                        }
                        if (ClpFlags & ClpSuspicion_DownloadCradle) {
                            Context->BehaviorFlags |= PN_BEHAVIOR_DOWNLOAD_CRADLE;
                        }
                        if (ClpFlags & ClpSuspicion_HiddenWindow) {
                            Context->BehaviorFlags |= PN_BEHAVIOR_SUSPICIOUS_PS;
                        }
                        if (ClpFlags & ClpSuspicion_LongCommand) {
                            Context->BehaviorFlags |= PN_BEHAVIOR_LONG_CMDLINE;
                        }
                        if (ClpFlags & ClpSuspicion_LOLBinAbuse) {
                            Context->Flags |= PN_PROC_FLAG_LOLBIN;
                        }

                        //
                        // Forward high-confidence CLP detections to BehaviorEngine.
                        // Use graduated event types based on what was found.
                        //
                        if (ClpFlags & ClpSuspicion_LOLBinAbuse) {
                            BeEngineSubmitEvent(
                                BehaviorEvent_LOLBinExecution,
                                BehaviorCategory_DefenseEvasion,
                                HandleToULong(Context->ProcessId),
                                ClpParsed, sizeof(CLP_PARSED_COMMAND),
                                ClpScore, FALSE, NULL);
                        }
                        if (ClpFlags & (ClpSuspicion_EncodedCommand | ClpSuspicion_ObfuscatedArgs)) {
                            BeEngineSubmitEvent(
                                BehaviorEvent_PowerShellExecution,
                                BehaviorCategory_ProcessExecution,
                                HandleToULong(Context->ProcessId),
                                ClpParsed, sizeof(CLP_PARSED_COMMAND),
                                ClpScore, FALSE, NULL);
                        }
                        if (ClpFlags & ClpSuspicion_DownloadCradle) {
                            BeEngineSubmitEvent(
                                BehaviorEvent_CommandLineExecution,
                                BehaviorCategory_ProcessExecution,
                                HandleToULong(Context->ProcessId),
                                ClpParsed, sizeof(CLP_PARSED_COMMAND),
                                ClpScore, FALSE, NULL);
                        }
                        if (ClpFlags & ClpSuspicion_ScriptExecution) {
                            BeEngineSubmitEvent(
                                BehaviorEvent_ScriptExecution,
                                BehaviorCategory_ProcessExecution,
                                HandleToULong(Context->ProcessId),
                                ClpParsed, sizeof(CLP_PARSED_COMMAND),
                                ClpScore, FALSE, NULL);
                        }

                        //
                        // Boost PN suspicion with CLP's superior score if higher
                        //
                        if (ClpScore > Context->SuspicionScore) {
                            Context->SuspicionScore = ClpScore;
                        }
                    }

                    ClpFreeParsed(ClpParsed);
                }
            }
        }
    }

    //
    // Environment variable analysis via EnvironmentMonitor.
    // Detects: PATH hijacking (T1574.007), DLL search order hijacking (T1574.008),
    // proxy manipulation (T1090.001), TEMP overrides, encoded payloads (T1027),
    // anomalous variable counts.
    //
    {
        PEM_MONITOR EmMonitor = PaGetEnvironmentMonitor();
        if (EmMonitor != NULL) {
            PEM_PROCESS_ENV EmEnv = NULL;
            NTSTATUS EmStatus;

            EmStatus = EmCaptureEnvironment(EmMonitor, Context->ProcessId, &EmEnv);
            if (NT_SUCCESS(EmStatus) && EmEnv != NULL) {
                EM_SUSPICION EmFlags = EmSuspicion_None;

                EmStatus = EmAnalyzeEnvironment(EmMonitor, EmEnv, &EmFlags);
                if (NT_SUCCESS(EmStatus) && EmFlags != EmSuspicion_None) {
                    //
                    // Map EM suspicion flags to PN behavior flags
                    //
                    if (EmFlags & EmSuspicion_DLLSearchOrder) {
                        Context->BehaviorFlags |= PN_BEHAVIOR_ENV_DLL_HIJACK;
                    }
                    if (EmFlags & EmSuspicion_EncodedValue) {
                        Context->BehaviorFlags |= PN_BEHAVIOR_ENV_ENCODED_VALUE;
                    }

                    //
                    // Forward high-confidence findings to BehaviorEngine
                    //
                    if (EmFlags & EmSuspicion_DLLSearchOrder) {
                        BeEngineSubmitEvent(
                            BehaviorEvent_DLLHijacking,
                            BehaviorCategory_PersistenceOperation,
                            (ULONG)(ULONG_PTR)Context->ProcessId,
                            &EmFlags, sizeof(EM_SUSPICION),
                            40, FALSE, NULL);
                    }
                    if (EmFlags & EmSuspicion_ProxySettings) {
                        BeEngineSubmitEvent(
                            BehaviorEvent_SandboxEvasion,
                            BehaviorCategory_DefenseEvasion,
                            (ULONG)(ULONG_PTR)Context->ProcessId,
                            &EmFlags, sizeof(EM_SUSPICION),
                            35, FALSE, NULL);
                    }
                    if (EmFlags & EmSuspicion_EncodedValue) {
                        BeEngineSubmitEvent(
                            BehaviorEvent_ProcessMasquerading,
                            BehaviorCategory_DefenseEvasion,
                            (ULONG)(ULONG_PTR)Context->ProcessId,
                            &EmFlags, sizeof(EM_SUSPICION),
                            30, FALSE, NULL);
                    }

                    //
                    // Boost suspicion score proportionally to finding count
                    //
                    ULONG EmBoost = 0;
                    if (EmFlags & EmSuspicion_ModifiedPath) EmBoost += 10;
                    if (EmFlags & EmSuspicion_DLLSearchOrder) EmBoost += 20;
                    if (EmFlags & EmSuspicion_ProxySettings) EmBoost += 15;
                    if (EmFlags & EmSuspicion_TempOverride) EmBoost += 10;
                    if (EmFlags & EmSuspicion_HiddenVariable) EmBoost += 5;
                    if (EmFlags & EmSuspicion_EncodedValue) EmBoost += 15;
                    if (Context->SuspicionScore + EmBoost <= 100) {
                        Context->SuspicionScore += EmBoost;
                    } else {
                        Context->SuspicionScore = 100;
                    }
                }

                EmReleaseEnvironment(EmEnv);
            }
        }
    }

    //
    // Handle forensics via HandleTracker.
    // Detects: cross-process injection handles (T1055), LSASS credential dumping
    // (T1003.001), token theft (T1134), high-privilege handle abuse, system handle
    // manipulation. Snapshots are transient â€” captured and released per-process.
    //
    {
        PHT_TRACKER HtTracker = PaGetHandleTracker();
        if (HtTracker != NULL) {
            PHT_PROCESS_HANDLES HtHandles = NULL;
            NTSTATUS HtStatus;

            HtStatus = HtSnapshotHandles(HtTracker, Context->ProcessId, &HtHandles);
            if (NT_SUCCESS(HtStatus) && HtHandles != NULL) {
                HT_SUSPICION HtFlags = HtSuspicion_None;
                ULONG HtScore = 0;

                HtStatus = HtAnalyzeHandles(HtTracker, HtHandles, &HtFlags, &HtScore);
                if (NT_SUCCESS(HtStatus) && HtFlags != HtSuspicion_None) {
                    //
                    // Map HT suspicion flags to PN behavior flags
                    //
                    if (HtFlags & HtSuspicion_InjectionCapable) {
                        Context->BehaviorFlags |= PN_BEHAVIOR_HANDLE_INJECTION;
                    }
                    if (HtFlags & HtSuspicion_CredentialAccess) {
                        Context->BehaviorFlags |= PN_BEHAVIOR_HANDLE_CRED_ACCESS;
                    }
                    if (HtFlags & HtSuspicion_TokenSteal) {
                        Context->BehaviorFlags |= PN_BEHAVIOR_HANDLE_TOKEN_STEAL;
                    }

                    //
                    // Forward high-confidence findings to BehaviorEngine
                    //
                    if (HtFlags & HtSuspicion_CredentialAccess) {
                        BeEngineSubmitEvent(
                            BehaviorEvent_CredentialDumping,
                            BehaviorCategory_CredentialAccess,
                            (ULONG)(ULONG_PTR)Context->ProcessId,
                            &HtFlags, sizeof(HT_SUSPICION),
                            40, FALSE, NULL);
                    }
                    if (HtFlags & HtSuspicion_InjectionCapable) {
                        BeEngineSubmitEvent(
                            BehaviorEvent_RemoteThreadCreate,
                            BehaviorCategory_CodeInjection,
                            (ULONG)(ULONG_PTR)Context->ProcessId,
                            &HtFlags, sizeof(HT_SUSPICION),
                            25, FALSE, NULL);
                    }
                    if (HtFlags & HtSuspicion_TokenSteal) {
                        BeEngineSubmitEvent(
                            BehaviorEvent_LSASSAccess,
                            BehaviorCategory_CredentialAccess,
                            (ULONG)(ULONG_PTR)Context->ProcessId,
                            &HtFlags, sizeof(HT_SUSPICION),
                            30, FALSE, NULL);
                    }

                    //
                    // Boost suspicion score
                    //
                    if (Context->SuspicionScore + HtScore <= 100) {
                        Context->SuspicionScore += HtScore;
                    } else {
                        Context->SuspicionScore = 100;
                    }
                }

                HtReleaseHandles(HtTracker, HtHandles);
            }
        }
    }

    //
    // LOLBin detection (case-insensitive)
    //
    if (Context->ImageFileName.Buffer != NULL &&
        Context->ImageFileName.Length > 0) {

        PWCHAR FileName = Context->ImageFileName.Buffer;

        //
        // Common LOLBins - Living Off The Land Binaries
        // These are legitimate Windows binaries often abused by attackers
        //
        static const PCWSTR LOLBins[] = {
            L"mshta.exe",
            L"regsvr32.exe",
            L"rundll32.exe",
            L"msiexec.exe",
            L"certutil.exe",
            L"bitsadmin.exe",
            L"wmic.exe",
            L"wscript.exe",
            L"cscript.exe",
            L"msbuild.exe",
            L"installutil.exe",
            L"regasm.exe",
            L"regsvcs.exe",
            L"msconfig.exe",
            L"cmstp.exe",
            L"forfiles.exe",
            L"pcalua.exe",
            L"presentationhost.exe",
            L"te.exe",
            L"dnscmd.exe",
            L"ftp.exe",
            L"hh.exe",
            L"ieexec.exe",
            L"infdefaultinstall.exe",
            L"mavinject.exe",
            L"msdeploy.exe",
            L"msdt.exe",
            L"odbcconf.exe",
            L"pcwrun.exe",
            L"rcsi.exe",
            L"sfc.exe",
            L"syncappvpublishingserver.exe",
            L"tracker.exe",
            L"verclsid.exe",
            L"xwizard.exe"
        };

        for (ULONG i = 0; i < ARRAYSIZE(LOLBins); i++) {
            if (_wcsicmp(FileName, LOLBins[i]) == 0) {
                Context->Flags |= PN_PROC_FLAG_LOLBIN;
                InterlockedIncrement64(&g_ProcessMonitor.Stats.LOLBinsDetected);
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}


static ULONG
PnpCalculateSuspicionScore(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Calculates a suspicion score based on accumulated indicators.
    Score ranges from 0-100.
--*/
{
    ULONG Score = 0;

    //
    // PPID spoofing is highly suspicious (major red flag)
    //
    if (Context->Flags & PN_PROC_FLAG_PPID_SPOOFED) {
        Score += 40;
    }

    //
    // Encoded command execution
    //
    if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
        Score += 25;
    }

    //
    // LOLBin execution (only suspicious with other indicators)
    //
    if (Context->Flags & PN_PROC_FLAG_LOLBIN) {
        Score += 15;

        //
        // LOLBin + encoded = much more suspicious
        //
        if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
            Score += 15;
        }

        //
        // LOLBin + download cradle = very suspicious
        //
        if (Context->BehaviorFlags & PN_BEHAVIOR_DOWNLOAD_CRADLE) {
            Score += 20;
        }
    }

    //
    // Cross-session process creation
    //
    if (Context->Flags & PN_PROC_FLAG_CROSS_SESSION) {
        Score += 10;
    }

    //
    // Unsigned binary (if signature verification enabled)
    //
    if (g_ProcessMonitor.Config.EnableSignatureVerification &&
        !(Context->Flags & PN_PROC_FLAG_SIGNATURE_VALID)) {
        Score += 5;
    }

    //
    // Behavioral flags
    //
    if (Context->BehaviorFlags & PN_BEHAVIOR_SUSPICIOUS_PS) {
        Score += 15;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_DOWNLOAD_CRADLE) {
        Score += 20;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_SUSPICIOUS_CMD) {
        Score += 10;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_LONG_CMDLINE) {
        Score += 5;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_REFLECTION_LOAD) {
        Score += 25;
    }

    //
    // Elevated + suspicious indicators = worse
    //
    if (Context->IsElevated && Score > 0) {
        Score += 10;
    }

    //
    // Dangerous privileges (rare in normal apps)
    //
    if (Context->HasDebugPrivilege && !Context->IsSystem) {
        Score += 15;
    }

    if (Context->HasTcbPrivilege && !Context->IsSystem) {
        Score += 20;  // Very suspicious if not SYSTEM
    }

    if (Context->HasAssignPrimaryTokenPrivilege && !Context->IsSystem) {
        Score += 15;
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}


// ============================================================================
// USER-MODE NOTIFICATION
// ============================================================================

static NTSTATUS
PnpSendProcessNotification(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ BOOLEAN IsCreation,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification = NULL;
    PSHADOWSTRIKE_PROCESS_VERDICT_REPLY Reply = NULL;
    SIZE_T NotificationSize;
    SIZE_T ReplySize = sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY);
    ULONG ReplySizeUlong = (ULONG)ReplySize;
    BOOLEAN RequireReply = FALSE;
    PUCHAR BufferPtr;

    USHORT ImagePathLen = 0;
    USHORT CmdLineLen = 0;

    //
    // Check if user-mode is connected
    //
    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return STATUS_PORT_DISCONNECTED;
    }

    //
    // Determine if we need a reply (blocking decision)
    //
    if (IsCreation && CreateInfo != NULL) {
        //
        // Require reply for suspicious processes
        //
        if (Context->SuspicionScore >= PN_SUSPICION_MEDIUM) {
            RequireReply = TRUE;
        }
    }

    //
    // Calculate sizes with validation
    //
    if (Context->ImagePath.Buffer != NULL) {
        ImagePathLen = Context->ImagePath.Length;
    }

    if (Context->CommandLine.Buffer != NULL) {
        CmdLineLen = Context->CommandLine.Length;

        //
        // Cap for message size
        //
        if (CmdLineLen > 4096) {
            CmdLineLen = 4096;
        }
    }

    //
    // Safe size calculation with overflow checking
    //
    SIZE_T BaseSize = sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION);
    SIZE_T DataSize = (SIZE_T)ImagePathLen + (SIZE_T)CmdLineLen;

    //
    // Check for overflow
    //
    if (DataSize < ImagePathLen || DataSize < CmdLineLen) {
        return STATUS_INTEGER_OVERFLOW;
    }

    NotificationSize = BaseSize + DataSize;
    if (NotificationSize < BaseSize || NotificationSize < DataSize) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Check against max message size
    //
    if (NotificationSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Truncate command line to fit
        //
        SIZE_T MaxData = SHADOWSTRIKE_MAX_MESSAGE_SIZE - BaseSize - ImagePathLen;
        if (MaxData < SHADOWSTRIKE_MAX_MESSAGE_SIZE) {  // Underflow check
            if (CmdLineLen > MaxData) {
                CmdLineLen = (USHORT)MaxData;
            }
        } else {
            CmdLineLen = 0;
        }
        NotificationSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Check pool limits
    //
    if (!PnpCheckPoolLimit(NotificationSize)) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.PoolLimitDrops);
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate notification buffer
    //
    Notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)ShadowStrikeAllocateMessageBuffer(
        (ULONG)NotificationSize
        );
    if (Notification == NULL) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PnpTrackPoolAllocation(NotificationSize);
    RtlZeroMemory(Notification, NotificationSize);

    //
    // Populate notification
    //
    Notification->ProcessId = HandleToULong(Context->ProcessId);
    Notification->ParentProcessId = HandleToULong(Context->ParentProcessId);
    Notification->CreatingProcessId = HandleToULong(Context->CreatingProcessId);
    Notification->CreatingThreadId = HandleToULong(Context->CreatingThreadId);
    Notification->Create = IsCreation;
    Notification->ImagePathLength = ImagePathLen;
    Notification->CommandLineLength = CmdLineLen;

    //
    // Copy variable data
    //
    BufferPtr = (PUCHAR)(Notification + 1);

    if (ImagePathLen > 0 && Context->ImagePath.Buffer != NULL) {
        RtlCopyMemory(BufferPtr, Context->ImagePath.Buffer, ImagePathLen);
        BufferPtr += ImagePathLen;
    }

    if (CmdLineLen > 0 && Context->CommandLine.Buffer != NULL) {
        RtlCopyMemory(BufferPtr, Context->CommandLine.Buffer, CmdLineLen);
    }

    //
    // Allocate reply buffer if needed
    //
    if (RequireReply) {
        Reply = (PSHADOWSTRIKE_PROCESS_VERDICT_REPLY)ShadowStrikeAllocateMessageBuffer(
            (ULONG)ReplySize
            );
        if (Reply == NULL) {
            RequireReply = FALSE;
        } else {
            PnpTrackPoolAllocation(ReplySize);
        }
    }

    //
    // Send notification with timeout
    //
    Status = ShadowStrikeSendProcessNotification(
        Notification,
        (ULONG)NotificationSize,
        RequireReply,
        Reply,
        RequireReply ? &ReplySizeUlong : NULL
        );

    //
    // Handle timeout
    //
    if (Status == STATUS_TIMEOUT) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.UserModeTimeouts);
        //
        // On timeout, default to allow (fail-open for availability)
        // Log for investigation
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] User-mode timeout for PID %lu, defaulting to ALLOW\n",
            HandleToULong(Context->ProcessId)
            );
        Status = STATUS_SUCCESS;
    }

    //
    // Handle verdict
    //
    if (RequireReply && NT_SUCCESS(Status) && Reply != NULL) {
        if (Reply->Verdict == Verdict_Malicious) {
            Status = STATUS_ACCESS_DENIED;
        }
    }

    //
    // Cleanup
    //
    if (Notification != NULL) {
        PnpTrackPoolFree(NotificationSize);
        ShadowStrikeFreeMessageBuffer(Notification);
    }

    if (Reply != NULL) {
        PnpTrackPoolFree(ReplySize);
        ShadowStrikeFreeMessageBuffer(Reply);
    }

    return Status;
}


// ============================================================================
// PROCESS TERMINATION HANDLING
// ============================================================================

static VOID
PnpHandleProcessTermination(
    _In_ HANDLE ProcessId
    )
{
    PPN_PROCESS_CONTEXT Context;

    //
    // Invalidate ProcessAnalyzer cache entry for this PID to prevent
    // stale analysis results on PID reuse.
    //
    if (g_ProcessMonitor.ProcessAnalyzer != NULL) {
        PaInvalidateProcess(
            (PPA_ANALYZER)g_ProcessMonitor.ProcessAnalyzer,
            ProcessId
            );
    }

    //
    // Notify centralized threat scoring engine of process exit
    // This triggers proper cleanup and reference release in the scoring engine
    //
    if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
        TsOnProcessExit(g_ProcessMonitor.ThreatScoringEngine, ProcessId);
    }

    //
    // Notify ThreadNotify module to clean up per-process thread tracking.
    // Must happen before context teardown to release EPROCESS references
    // and free thread event history for this process.
    //
    TnNotifyProcessTermination(ProcessId);

    //
    // Notify WSLMonitor to remove the WSL tracking entry for this process.
    // Without this, every WSL process leaks its NonPagedPool tracking
    // structure and consumes a slot toward the 512 capacity limit.
    //
    WslMonProcessTerminated(ProcessId);

    //
    // Notify RegistryCallback to clean up per-process registry context.
    // Without this, the EPROCESS reference and NonPagedPool tracking
    // entry leak for every process that performed registry operations.
    //
    ShadowStrikeRegistryProcessTerminated(ProcessId);

    //
    // Notify ALPC port monitor to remove port entries owned by this process.
    // Without this, stale entries survive until TTL expiry (5 minutes),
    // during which PID reuse inherits the wrong security context.
    //
    ShadowAlpcProcessTerminated(ProcessId);

    //
    // Notify TokenAnalyzer to clean up baseline + cached token entries
    // for this process. Prevents unbounded memory growth.
    //
    {
        PTA_ANALYZER tokenAnalyzer = PaGetTokenAnalyzer();
        if (tokenAnalyzer != NULL) {
            TaOnProcessTerminated(tokenAnalyzer, ProcessId);
        }
    }

    //
    // Remove process from relationship graph before context teardown.
    // Must happen while process context is still accessible â€” enables
    // final cluster scoring and relationship cleanup.
    //
    {
        PPR_GRAPH prGraph = PaGetProcessRelationshipGraph();
        if (prGraph != NULL) {
            PrRemoveProcess(prGraph, ProcessId);
        }
    }

    //
    // Remove process from trusted PID set (bitmap or hash table).
    // Must happen on termination to prevent stale entries and PID reuse
    // inheriting wrong trust state.
    //
    ShadowStrikeOnProcessTerminate(ProcessId);

    //
    // Clean up MemoryMonitor process context and stop HeapSpray tracking.
    // Releases EPROCESS ref held by HeapSpray detector for this PID.
    //
    MmMonitorRemoveProcessContext(HandleToULong(ProcessId));

    //
    // Clean up SyscallMonitor per-process state (NTDLL ranges, call caches).
    // Also cascades to CallstackAnalyzer and HeavensGateDetector sub-module cleanup.
    // Must happen on termination to prevent context leak (max 8192 tracked).
    //
    ScMonitorRemoveProcessContext(HandleToULong(ProcessId));

    //
    // Look up process context
    //
    Context = PnpLookupProcessContext(ProcessId);
    if (Context == NULL) {
        return;
    }

    //
    // Record termination time
    //
    KeQuerySystemTime(&Context->TerminateTime);

    //
    // Send termination notification (fire-and-forget)
    //
    PnpSendProcessNotification(Context, FALSE, NULL);

    //
    // Also notify via ScanBridge for consistent telemetry pipeline coverage.
    // Thread/Image/Registry notifications all go through ScanBridge;
    // process termination should too for circuit breaker + stats tracking.
    //
    ShadowStrikeSendProcessEvent(
        Context->ProcessId,
        Context->ParentProcessId,
        FALSE,
        &Context->ImagePath,
        NULL
    );

    //
    // Stream process termination event to telemetry buffer.
    //
    {
        PTB_MANAGER tbMgr = ShadowStrikeGetTelemetryBuffer();
        if (tbMgr != NULL) {
            struct {
                ULONG ProcessId;
                ULONG ParentProcessId;
                ULONG SessionId;
                ULONG ExitCode;
            } tbPayload;
            tbPayload.ProcessId = HandleToULong(Context->ProcessId);
            tbPayload.ParentProcessId = HandleToULong(Context->ParentProcessId);
            tbPayload.SessionId = Context->SessionId;
            tbPayload.ExitCode = 0;
            TbEnqueue(tbMgr, TbEntryType_ProcessTerminate,
                      &tbPayload, sizeof(tbPayload), NULL);
        }
    }

    //
    // Emit ETW telemetry for process termination
    //
    TeLogProcessTerminate(
        HandleToULong(Context->ProcessId),
        0  // ExitCode not reliably available at PASSIVE_LEVEL cleanup
    );

    //
    // Commit (discard) any pending file backup entries for this process.
    // If the process exited normally without triggering a ransomware verdict,
    // its backed-up files are no longer needed and disk space can be reclaimed.
    //
    FbeCommitProcess(ProcessId);

    //
    // Clean up PreAcquireSection behavioral context for this process.
    // Prevents stale mapping data and PID recycling issues.
    //
    ShadowStrikeRemoveProcessMappingContext(ProcessId);

    //
    // Clean up PreSetInfo behavioral context for this process.
    // Prevents stale ransomware/destruction scores persisting after PID recycle.
    //
    ShadowStrikeRemovePreSetInfoProcessContext(ProcessId);

    //
    // Remove from MessageHandler protected process list (if registered).
    // Without this, PID reuse inherits privileged message authorization â€”
    // a new process with the recycled PID can send push/whitelist/exclusion
    // commands that require protected-process auth. CRITICAL security fix.
    //
    MhUnprotectProcess((UINT32)(ULONG_PTR)ProcessId);

    //
    // Remove from ObjectCallback protected process list (if registered).
    // This is a no-op if the PID was never added â€” safe to call unconditionally.
    //
    ObRemoveProtectedProcess(ProcessId);

    //
    // Invalidate cached well-known PIDs for this process.
    // Prevents PID reuse attacks where a new process inherits LSASS/CSRSS
    // protected status from the terminated process's cached PID.
    //
    ObInvalidateCachedPid(ProcessId);

    //
    // Remove AMSI bypass detector tracking for this process.
    // Prevents tracker leaks and stale entries after PID recycle.
    //
    AbdRemoveProcessTracking(ProcessId);

    //
    // Remove C2Detection process context for this process.
    // Prevents process context accumulation (capped at 4096).
    //
    {
        PC2_DETECTOR c2det = NfFilterGetC2Detector();
        if (c2det != NULL) {
            C2ProcessTerminated(c2det, ProcessId);
        }
    }

    //
    // Remove ConnectionTracker process context for this process.
    // Prevents CT_PROCESS_CONTEXT accumulation with stale EPROCESS refs.
    //
    {
        PCONNECTION_TRACKER ctTracker = (PCONNECTION_TRACKER)NfFilterGetConnectionTracker();
        if (ctTracker != NULL) {
            CtProcessTerminated(ctTracker, ProcessId);
        }
    }

    //
    // Remove DataExfiltration transfer contexts for this process.
    // Prevents DX_TRANSFER_CONTEXT accumulation for short-lived processes
    // and ensures stale per-process DLP data doesn't skew detection.
    //
    {
        PDX_DETECTOR dxDet = NfFilterGetDxDetector();
        if (dxDet != NULL) {
            DxProcessTerminated(dxDet, ProcessId);
        }
    }

    //
    // Remove DnsMonitor process context for this process.
    // Prevents DNS_PROCESS_CONTEXT accumulation and stale tunneling state.
    //
    {
        PDNS_MONITOR dnsMon = NfFilterGetDnsMonitor();
        if (dnsMon != NULL) {
            DnsProcessTerminated(dnsMon, ProcessId);
        }
    }

    //
    // Clean up PatternMatcher per-process match states for this process.
    // Without cleanup, partial match states (PM_MATCH_STATE_INTERNAL) accumulate
    // in NonPaged pool indefinitely â€” each ~600 bytes with event tracking arrays.
    // Also prevents stale PIDs from producing false behavioral matches after recycle.
    //
    {
        PPM_MATCHER pmMatcher = BeGetPatternMatcher();
        if (pmMatcher != NULL) {
            PmCleanupProcessStates(pmMatcher, ProcessId);
        }
    }

    //
    // Remove HandleProtection per-process tracking for this process.
    // Prevents HP_PROCESS_CONTEXT accumulation (~256 bytes + handle entries each)
    // and ensures stale EPROCESS refs don't survive PID recycle.
    //
    {
        PHP_PROTECTION_ENGINE hpEngine = ShadowStrikeGetHandleProtection();
        if (hpEngine != NULL) {
            HpProcessTerminated(hpEngine, ProcessId);
        }
    }

    //
    // Remove SelfProtect protection entry for this process.
    // Without this, the PEPROCESS reference leaks (ObReferenceObject held
    // indefinitely) and the PID slot cannot be reused â€” new protected process
    // registrations will hit the 16-entry cap and fail.
    //
    ShadowStrikeUnprotectProcess(ProcessId);

    //
    // Remove ResourceThrottling per-process quota for this process.
    // Prevents RT_PROCESS_QUOTA accumulation (~310 bytes each) and
    // stale throttle state surviving PID recycle.
    //
    {
        PRT_THROTTLER rtThrottler = ShadowStrikeGetResourceThrottler();
        if (rtThrottler != NULL) {
            RtRemoveProcess(rtThrottler, ProcessId);
        }
    }

    //
    // Remove protected PID from AntiUnload on process termination.
    // Without this, terminated processes remain in the 32-slot protected
    // PID table forever â€” after 32 registrations the table is permanently
    // full and AuProtectProcess returns STATUS_INSUFFICIENT_RESOURCES.
    //
    {
        PAU_PROTECTOR auProtector = ShadowStrikeGetAntiUnloadProtector();
        if (auProtector != NULL) {
            AuUnprotectProcess(auProtector, ProcessId);
        }
    }

    //
    // Remove clipboard monitor tracking for this process.
    // Without cleanup, tracking table fills to 2048 and module goes deaf.
    //
    CbMonRemoveProcess(ProcessId);

    //
    // Remove creating process context from ProcessUtils hash table.
    // Must happen before context teardown â€” frees the entry that was
    // stored at process creation time for anti-PPID-spoofing detection.
    //
    ShadowStrikeRemoveCreatingProcessContext(ProcessId);

    //
    // Release per-process module tracking in ImageNotify.
    // Without cleanup, loaded DLL lists accumulate in NonPaged pool permanently.
    //
    ImageNotifyProcessTerminated(ProcessId);

    //
    // Mark process as terminated in PrivilegeMonitor for deferred baseline cleanup.
    // The monitor's periodic timer will garbage-collect the baseline after timeout.
    //
    if (g_ProcessMonitor.PrivilegeMonitor != NULL) {
        PmMarkProcessTerminated(
            (PPM_MONITOR)g_ProcessMonitor.PrivilegeMonitor,
            ProcessId
            );
    }

    //
    // Notify InjectionDetector of process exit so it can clean up the
    // per-process injection context. Without this, injection chain contexts
    // accumulate indefinitely in NonPaged pool â€” a memory leak per-process.
    //
    MmMonitorNotifyInjectionProcessExit(ProcessId);

    //
    // Remove from tracking
    //
    PnpRemoveProcessContext(Context);

    //
    // Release lookup reference
    //
    PnpDereferenceContext(Context);
}


// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static BOOLEAN
PnpIsKnownSystemProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PEPROCESS Process
    )
/*++
Routine Description:
    Determines if a process is a known system process.

    This is a PERFORMANCE optimization, not a security control.
    We skip detailed analysis for core system processes that
    are always present and trusted.
--*/
{
    ULONG Pid = HandleToULong(ProcessId);

    //
    // System (4) and Idle (0) - always system
    //
    if (Pid <= 4) {
        return TRUE;
    }

    //
    // For other processes, we could check:
    // 1. Protected process status
    // 2. Image path against known system binaries
    // 3. Token for SYSTEM SID
    //
    // However, PIDs are dynamic and attackers can abuse any process,
    // so we only skip the absolute minimum here.
    //

    UNREFERENCED_PARAMETER(Process);

    return FALSE;
}


static BOOLEAN
PnpIsTrustedProcess(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Determines if a process should be considered trusted.

    SECURITY NOTE: This check can be bypassed and should NOT be the
    sole basis for allowing potentially malicious behavior.

    Trust is only granted when:
    1. Binary is in a protected system path
    2. Binary has valid signature
    3. No suspicious indicators are present
--*/
{
    //
    // Never trust if PPID spoofed
    //
    if (Context->Flags & PN_PROC_FLAG_PPID_SPOOFED) {
        return FALSE;
    }

    //
    // Never trust if encoded commands
    //
    if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
        return FALSE;
    }

    //
    // Require valid signature for trust
    //
    if (g_ProcessMonitor.Config.EnableSignatureVerification) {
        if (!(Context->Flags & PN_PROC_FLAG_SIGNATURE_VALID)) {
            return FALSE;
        }
    }

    //
    // Check for Windows system paths
    //
    if (Context->ImagePath.Buffer != NULL && Context->ImagePath.Length > 0) {
        //
        // Use case-insensitive, length-bounded search
        //
        if (PnpSafeWcsStrI(Context->ImagePath.Buffer,
                          Context->ImagePath.Length,
                          L"\\Windows\\System32\\") ||
            PnpSafeWcsStrI(Context->ImagePath.Buffer,
                          Context->ImagePath.Length,
                          L"\\Windows\\SysWOW64\\") ||
            PnpSafeWcsStrI(Context->ImagePath.Buffer,
                          Context->ImagePath.Length,
                          L"\\Windows\\WinSxS\\")) {

            //
            // Additional validation: check for path traversal attempts
            //
            if (PnpSafeWcsStrI(Context->ImagePath.Buffer,
                              Context->ImagePath.Length,
                              L"..")) {
                return FALSE;  // Path traversal attempt
            }

            return TRUE;
        }
    }

    return FALSE;
}


static BOOLEAN
PnpCheckParentSessionMatch(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Checks if parent and child sessions match.
    Cross-session process creation can indicate token manipulation.
--*/
{
    //
    // Same session = normal
    //
    if (Context->SessionId == Context->ParentSessionId) {
        return TRUE;
    }

    //
    // Exception: Parent is session 0 (service), child is user session
    // This is normal for service-launched processes
    //
    if (Context->ParentSessionId == 0 && Context->SessionId != 0) {
        return TRUE;
    }

    //
    // User session creating session-0 process is suspicious
    //
    if (Context->ParentSessionId != 0 && Context->SessionId == 0) {
        return FALSE;
    }

    //
    // Different user sessions is unusual
    //
    return FALSE;
}


static BOOLEAN
PnpCheckRateLimit(
    VOID
    )
/*++
Routine Description:
    Implements token bucket rate limiting for notifications.

Return Value:
    TRUE if notification is allowed, FALSE if rate limited.
--*/
{
    LARGE_INTEGER CurrentTime;
    LONG64 WindowStart;
    LONG64 WindowDuration;
    LONG CurrentCount;

    KeQuerySystemTime(&CurrentTime);

    //
    // Window duration in 100ns units
    //
    WindowDuration = (LONG64)PN_RATE_LIMIT_WINDOW_MS * 10000;

    //
    // Check if we need to reset the window
    //
    WindowStart = InterlockedCompareExchange64(
        &g_ProcessMonitor.RateLimiter.WindowStartTime,
        0, 0);

    if ((CurrentTime.QuadPart - WindowStart) > WindowDuration) {
        //
        // Try to reset window
        //
        if (InterlockedCompareExchange64(
                &g_ProcessMonitor.RateLimiter.WindowStartTime,
                CurrentTime.QuadPart,
                WindowStart) == WindowStart) {
            //
            // We reset the window, reset counter
            //
            InterlockedExchange(&g_ProcessMonitor.RateLimiter.NotificationsInWindow, 0);
        }
    }

    //
    // Increment and check count
    //
    CurrentCount = InterlockedIncrement(&g_ProcessMonitor.RateLimiter.NotificationsInWindow);

    if (CurrentCount > (LONG)g_ProcessMonitor.Config.MaxNotificationsPerSecond) {
        InterlockedIncrement(&g_ProcessMonitor.RateLimiter.DroppedNotifications);
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN
PnpCheckPoolLimit(
    _In_ SIZE_T AllocationSize
    )
/*++
Routine Description:
    Checks if allocation would exceed pool limits.
--*/
{
    LONG64 Current = InterlockedCompareExchange64(
        &g_ProcessMonitor.PoolTracker.CurrentAllocation, 0, 0);

    if ((Current + (LONG64)AllocationSize) > g_ProcessMonitor.PoolTracker.MaxAllocation) {
        return FALSE;
    }

    return TRUE;
}


static VOID
PnpTrackPoolAllocation(
    _In_ SIZE_T Size
    )
{
    LONG64 NewValue = InterlockedAdd64(
        &g_ProcessMonitor.PoolTracker.CurrentAllocation,
        (LONG64)Size);

    //
    // Update peak
    //
    LONG64 Peak = InterlockedCompareExchange64(
        &g_ProcessMonitor.PoolTracker.PeakAllocation, 0, 0);

    while (NewValue > Peak) {
        LONG64 OldPeak = InterlockedCompareExchange64(
            &g_ProcessMonitor.PoolTracker.PeakAllocation,
            NewValue,
            Peak);
        if (OldPeak == Peak) {
            break;
        }
        Peak = OldPeak;
    }
}


static VOID
PnpTrackPoolFree(
    _In_ SIZE_T Size
    )
{
    InterlockedAdd64(
        &g_ProcessMonitor.PoolTracker.CurrentAllocation,
        -(LONG64)Size);
}


static BOOLEAN
PnpSafeWcsStrI(
    _In_ PCWCH Buffer,
    _In_ USHORT BufferLengthBytes,
    _In_ PCWSTR Pattern
    )
/*++
Routine Description:
    Case-insensitive substring search with length bounds.
    Does NOT rely on null-termination.

Arguments:
    Buffer - The buffer to search in
    BufferLengthBytes - Length of buffer in BYTES
    Pattern - Null-terminated pattern to search for

Return Value:
    TRUE if pattern found, FALSE otherwise.
--*/
{
    SIZE_T BufferLenChars;
    SIZE_T PatternLen;
    SIZE_T i, j;

    if (Buffer == NULL || Pattern == NULL || BufferLengthBytes == 0) {
        return FALSE;
    }

    BufferLenChars = BufferLengthBytes / sizeof(WCHAR);
    PatternLen = wcslen(Pattern);

    if (PatternLen == 0 || PatternLen > BufferLenChars) {
        return FALSE;
    }

    //
    // Simple case-insensitive search
    //
    for (i = 0; i <= BufferLenChars - PatternLen; i++) {
        BOOLEAN Match = TRUE;

        for (j = 0; j < PatternLen; j++) {
            WCHAR BufChar = Buffer[i + j];
            WCHAR PatChar = Pattern[j];

            //
            // Convert to uppercase for comparison
            //
            if (BufChar >= L'a' && BufChar <= L'z') {
                BufChar -= (L'a' - L'A');
            }
            if (PatChar >= L'a' && PatChar <= L'z') {
                PatChar -= (L'a' - L'A');
            }

            if (BufChar != PatChar) {
                Match = FALSE;
                break;
            }
        }

        if (Match) {
            return TRUE;
        }
    }

    return FALSE;
}


static NTSTATUS
PnpVerifyImageSignature(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Verifies the digital signature of the process image.

    This uses CI.dll exports if available, or falls back to
    checking basic signature status from the process object.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Check if process object has signature info
    // This is available via PsGetProcessSignatureLevel on Win8.1+
    //
    if (Context->ProcessObject != NULL) {
        UCHAR SignatureLevel = 0;
        UCHAR SectionSignatureLevel = 0;

        //
        // PsGetProcessSignatureLevel is available on Windows 8.1+
        // Returns VOID, populates output params directly
        //
        #if (NTDDI_VERSION >= NTDDI_WINBLUE)
        PsGetProcessSignatureLevel(
            Context->ProcessObject,
            &SignatureLevel,
            &SectionSignatureLevel
            );

        //
        // Any signature level > 0 indicates some form of signing
        // SE_SIGNING_LEVEL_MICROSOFT (8) or higher is MS-signed
        // SE_SIGNING_LEVEL_AUTHENTICODE (4) is third-party signed
        //
        if (SignatureLevel >= SE_SIGNING_LEVEL_AUTHENTICODE) {
            Context->IsSignatureValid = TRUE;
        }
        #else
        //
        // Older OS - can't easily verify, default to unknown
        //
        Status = STATUS_NOT_SUPPORTED;
        #endif
    }

    return Status;
}


// ============================================================================
// PERIODIC SECURITY CHECKS (Privilege Escalation + Token Manipulation)
// ============================================================================

//
// Maximum number of active processes to check per timer cycle.
// Prevents the timer callback from monopolizing CPU.
//
#define PN_MAX_SECURITY_CHECKS_PER_CYCLE    64

static VOID
PnpPeriodicSecurityChecks(
    VOID
    )
/*++
Routine Description:
    Iterates active (non-terminated) process contexts and performs
    runtime privilege escalation detection (PmCheckForEscalation)
    and token manipulation detection (TaDetectTokenManipulation).

    This is the sole consumer of these detection APIs, activating
    privilege/token monitoring that was previously dormant.

    MITRE Coverage:
    - T1134: Access Token Manipulation
    - T1134.001: Token Impersonation/Theft
    - T1134.002: Create Process with Token
    - T1548: Abuse Elevation Control Mechanism
    - T1068: Exploitation for Privilege Escalation

    Runs at PASSIVE_LEVEL from timer WorkItem callback.
--*/
{
    PLIST_ENTRY Entry;
    PPN_PROCESS_CONTEXT Context;
    PPM_MONITOR PrivMonitor;
    PTA_ANALYZER TokenAnalyzer;
    ULONG CheckCount = 0;

    PAGED_CODE();

    PrivMonitor = (PPM_MONITOR)g_ProcessMonitor.PrivilegeMonitor;
    TokenAnalyzer = (PTA_ANALYZER)g_ProcessMonitor.TokenAnalyzer;

    //
    // Both modules must be available
    //
    if (PrivMonitor == NULL && TokenAnalyzer == NULL) {
        return;
    }

    //
    // Walk the active process list under shared lock.
    // We only collect PIDs here; actual detection calls happen
    // outside the lock to minimize hold time.
    //
    HANDLE ProcessIds[PN_MAX_SECURITY_CHECKS_PER_CYCLE];
    ULONG PidCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProcessMonitor.ProcessListLock);

    for (Entry = g_ProcessMonitor.ProcessList.Flink;
         Entry != &g_ProcessMonitor.ProcessList && PidCount < PN_MAX_SECURITY_CHECKS_PER_CYCLE;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Skip terminated processes â€” no point checking dead contexts
        //
        if (Context->TerminateTime.QuadPart != 0) {
            continue;
        }

        //
        // Skip system/idle/low-PID processes
        //
        if ((ULONG_PTR)Context->ProcessId <= 4) {
            continue;
        }

        ProcessIds[PidCount++] = Context->ProcessId;
    }

    ExReleasePushLockShared(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Now run detection checks outside the lock
    //
    for (ULONG i = 0; i < PidCount; i++) {
        HANDLE Pid = ProcessIds[i];

        if (g_ProcessMonitor.ShutdownRequested) {
            break;
        }

        //
        // Privilege escalation check (T1548, T1068)
        //
        if (PrivMonitor != NULL) {
            PPM_ESCALATION_EVENT EscEvent = NULL;
            NTSTATUS pmStatus = PmCheckForEscalation(
                PrivMonitor,
                Pid,
                &EscEvent
                );

            if (pmStatus == STATUS_SUCCESS && EscEvent != NULL) {
                //
                // Escalation detected â€” submit to BehaviorEngine
                //
                BeEngineSubmitEvent(
                    BehaviorEvent_PrivilegeEscalation,
                    BehaviorCategory_PrivilegeOperation,
                    HandleToULong(Pid),
                    &EscEvent->Type,
                    sizeof(PM_ESCALATION_TYPE),
                    EscEvent->SuspicionScore,
                    FALSE,
                    NULL
                    );

                InterlockedIncrement64(&g_ProcessMonitor.Stats.SecurityChecksTriggered);
                PmDereferenceEvent(EscEvent);
            }
        }

        //
        // Token manipulation check (T1134)
        //
        if (TokenAnalyzer != NULL) {
            TA_TOKEN_ATTACK Attack = TaAttack_None;
            ULONG TokenScore = 0;
            NTSTATUS taStatus = TaDetectTokenManipulation(
                TokenAnalyzer,
                Pid,
                &Attack,
                &TokenScore
                );

            if (NT_SUCCESS(taStatus) && Attack != TaAttack_None && TokenScore > 0) {
                //
                // Token attack detected â€” submit to BehaviorEngine
                //
                BeEngineSubmitEvent(
                    BehaviorEvent_TokenManipulation,
                    BehaviorCategory_PrivilegeOperation,
                    HandleToULong(Pid),
                    &Attack,
                    sizeof(TA_TOKEN_ATTACK),
                    TokenScore,
                    FALSE,
                    NULL
                    );

                InterlockedIncrement64(&g_ProcessMonitor.Stats.SecurityChecksTriggered);
            }
        }

        CheckCount++;
    }

    //
    // Process Relationship Graph Analysis â€” detect suspicious clusters
    // of related processes that may indicate coordinated attack activity
    // (e.g., multiple injection chains, lateral movement patterns).
    // Runs once per security check cycle (not per-process) at PASSIVE_LEVEL.
    //
    {
        PPR_GRAPH prGraph = PaGetProcessRelationshipGraph();
        if (prGraph != NULL) {
            HANDLE suspiciousPids[32];
            ULONG suspiciousCount = 0;

            NTSTATUS prStatus = PrFindSuspiciousClusters(
                prGraph,
                suspiciousPids,
                ARRAYSIZE(suspiciousPids),
                &suspiciousCount
                );

            if (NT_SUCCESS(prStatus) && suspiciousCount > 0) {
                for (ULONG c = 0; c < suspiciousCount; c++) {
                    BeEngineSubmitEvent(
                        BehaviorEvent_SuspiciousParentChild,
                        BehaviorCategory_ProcessExecution,
                        HandleToULong(suspiciousPids[c]),
                        &suspiciousCount,
                        sizeof(ULONG),
                        60,
                        FALSE,
                        NULL
                        );

                    InterlockedIncrement64(&g_ProcessMonitor.Stats.SecurityChecksTriggered);
                }
            }
        }
    }
}


// ============================================================================
// TIMER AND CLEANUP
// ============================================================================

static VOID
PnpCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    TimerManager callback for periodic process context cleanup.
    Runs at PASSIVE_LEVEL via TmFlag_WorkItemCallback.

    Re-entrancy guard: CleanupWorkPending prevents overlapping
    cleanup cycles if the previous one hasn't finished.
--*/
{
    UNREFERENCED_PARAMETER(TimerId);
    UNREFERENCED_PARAMETER(Context);

    if (g_ProcessMonitor.ShutdownRequested) {
        return;
    }

    //
    // Prevent overlapping cleanup
    //
    if (InterlockedCompareExchange(&g_ProcessMonitor.CleanupWorkPending, TRUE, FALSE) != FALSE) {
        return;
    }

    PnpCleanupStaleContexts();

    //
    // Periodic privilege escalation and token manipulation detection.
    // Iterate active (non-terminated) contexts and check for runtime
    // privilege changes and token attacks (T1134, T1548).
    // PASSIVE_LEVEL guaranteed by TmFlag_WorkItemCallback.
    //
    PnpPeriodicSecurityChecks();

    //
    // Run ThreatScoring maintenance on the ProcessMonitor's engine.
    // This decays factor scores over time and purges contexts for
    // terminated processes, preventing unbounded memory growth.
    // Timer runs at PASSIVE_LEVEL via TmFlag_WorkItemCallback. âœ“
    //
    if (g_ProcessMonitor.ThreatScoringEngine != NULL) {
        TsRunMaintenancePass(g_ProcessMonitor.ThreatScoringEngine);
        TsPurgeStaleContexts(g_ProcessMonitor.ThreatScoringEngine, NULL);
    }

    InterlockedExchange(&g_ProcessMonitor.CleanupWorkPending, FALSE);
}


static VOID
PnpCleanupStaleContexts(
    VOID
    )
/*++
Routine Description:
    Removes process contexts for terminated processes.

    This runs periodically to clean up contexts that weren't
    properly removed during process termination, and to check
    for orphaned contexts where the process has exited.
--*/
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PPN_PROCESS_CONTEXT Context;
    LIST_ENTRY StaleList;

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)PN_CONTEXT_TIMEOUT_MS * 10000;

    //
    // Collect stale contexts while holding lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    for (Entry = g_ProcessMonitor.ProcessList.Flink;
         Entry != &g_ProcessMonitor.ProcessList;
         Entry = Next) {

        Next = Entry->Flink;
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        BOOLEAN ShouldRemove = FALSE;

        //
        // Check if process has terminated (TerminateTime set)
        //
        if (Context->TerminateTime.QuadPart != 0) {
            //
            // Check if enough time has passed since termination
            //
            if ((CurrentTime.QuadPart - Context->TerminateTime.QuadPart) > TimeoutInterval.QuadPart) {
                ShouldRemove = TRUE;
            }
        } else {
            //
            // Process hasn't called termination callback
            // Check if it's actually still running
            //
            if (Context->ProcessObject != NULL) {
                //
                // Check if process has exited
                //
                if (PsGetProcessExitStatus(Context->ProcessObject) != STATUS_PENDING) {
                    //
                    // Process has exited but we missed termination callback
                    //
                    KeQuerySystemTime(&Context->TerminateTime);
                    ShouldRemove = TRUE;
                }
            }
        }

        if (ShouldRemove) {
            //
            // Remove from main list
            //
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedExchange(&Context->InsertedInList, FALSE);
            InterlockedDecrement(&g_ProcessMonitor.ProcessCount);

            //
            // Add to stale list for hash removal outside this lock
            //
            InsertTailList(&StaleList, &Context->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Remove from hash tables and free - outside ProcessListLock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Remove from hash table under correct bucket lock
        //
        if (InterlockedCompareExchange(&Context->InsertedInHash, FALSE, TRUE)) {
            ULONG BucketIndex = PnpHashProcessId(Context->ProcessId);
            PPN_HASH_BUCKET Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Bucket->Lock);

            if (!IsListEmpty(&Context->HashEntry)) {
                RemoveEntryList(&Context->HashEntry);
                InitializeListHead(&Context->HashEntry);
            }

            ExReleasePushLockExclusive(&Bucket->Lock);
            KeLeaveCriticalRegion();
        }

        //
        // Release the list reference (will free if last ref)
        //
        PnpDereferenceContext(Context);
    }
}


// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

NTSTATUS
ShadowStrikeGetProcessMonitorStats(
    _Out_opt_ PULONG64 ProcessCreations,
    _Out_opt_ PULONG64 ProcessesBlocked,
    _Out_opt_ PULONG64 PpidSpoofingDetected,
    _Out_opt_ PULONG64 SuspiciousProcesses
    )
{
    if (!g_ProcessMonitor.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (ProcessCreations != NULL) {
        *ProcessCreations = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.ProcessCreations, 0, 0);
    }

    if (ProcessesBlocked != NULL) {
        *ProcessesBlocked = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.ProcessesBlocked, 0, 0);
    }

    if (PpidSpoofingDetected != NULL) {
        *PpidSpoofingDetected = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.PpidSpoofingDetected, 0, 0);
    }

    if (SuspiciousProcesses != NULL) {
        *SuspiciousProcesses = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.SuspiciousProcesses, 0, 0);
    }

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeQueryProcessContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG Flags,
    _Out_opt_ PULONG SuspicionScore
    )
{
    PPN_PROCESS_CONTEXT Context;

    if (!g_ProcessMonitor.Initialized) {
        return STATUS_NOT_FOUND;
    }

    Context = PnpLookupProcessContext(ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (Flags != NULL) {
        *Flags = Context->Flags;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = Context->SuspicionScore;
    }

    PnpDereferenceContext(Context);

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeGetProcessMonitorExtendedStats(
    _Out_opt_ PULONG64 RateLimitDrops,
    _Out_opt_ PULONG64 PoolLimitDrops,
    _Out_opt_ PULONG64 UserModeTimeouts,
    _Out_opt_ PULONG64 CurrentPoolUsage,
    _Out_opt_ PULONG64 PeakPoolUsage
    )
{
    if (!g_ProcessMonitor.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (RateLimitDrops != NULL) {
        *RateLimitDrops = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.RateLimitDrops, 0, 0);
    }

    if (PoolLimitDrops != NULL) {
        *PoolLimitDrops = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.PoolLimitDrops, 0, 0);
    }

    if (UserModeTimeouts != NULL) {
        *UserModeTimeouts = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.UserModeTimeouts, 0, 0);
    }

    if (CurrentPoolUsage != NULL) {
        *CurrentPoolUsage = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.PoolTracker.CurrentAllocation, 0, 0);
    }

    if (PeakPoolUsage != NULL) {
        *PeakPoolUsage = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.PoolTracker.PeakAllocation, 0, 0);
    }

    return STATUS_SUCCESS;
}
