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
 * ShadowStrike NGAV - ENTERPRISE PRE-SET-INFORMATION CALLBACK ENGINE
 * ============================================================================
 *
 * @file PreSetInfo.c
 * @brief Enterprise-grade IRP_MJ_SET_INFORMATION pre-operation callback.
 *
 * Implements Enterprise-grade file set information monitoring with:
 * - Self-protection for AV files (delete/rename blocking)
 * - Ransomware detection via mass rename/delete patterns
 * - Data destruction prevention (mass deletion detection)
 * - File attribute manipulation monitoring
 * - Hard link creation monitoring (credential harvesting detection)
 * - Short name manipulation detection (8.3 name abuse)
 * - End-of-file truncation monitoring (data wiping)
 * - File disposition tracking (delete-on-close)
 * - Rename target validation (path traversal prevention)
 * - Per-process behavioral analysis
 * - Comprehensive telemetry and statistics
 *
 * FILE_INFORMATION_CLASS Coverage:
 * - FileDispositionInformation/Ex: Delete operations
 * - FileRenameInformation/Ex: Rename operations
 * - FileLinkInformation/Ex: Hard link creation
 * - FileShortNameInformation: 8.3 name changes
 * - FileEndOfFileInformation: Truncation/expansion
 * - FileAllocationInformation: Space allocation
 * - FileBasicInformation: Attribute/timestamp changes
 * - FileValidDataLengthInformation: Valid data changes
 *
 * MITRE ATT&CK Coverage:
 * - T1486: Data Encrypted for Impact (ransomware rename patterns)
 * - T1485: Data Destruction (mass deletion detection)
 * - T1070.004: File Deletion (evidence destruction)
 * - T1036: Masquerading (extension change detection)
 * - T1564.004: NTFS File Attributes (hidden attribute abuse)
 * - T1003.001: LSASS Memory (hard link to SAM/SECURITY)
 * - T1562.001: Impair Defenses (AV file tampering)
 *
 * Performance Characteristics:
 * - Early exit for kernel-mode and excluded processes
 * - O(1) PID lookup for exclusions
 * - Minimal string operations on hot paths
 * - Lock-free statistics using InterlockedXxx
 * - Configurable thresholds for detection
 *
 * Security Fixes (v2.1.0):
 * - Fixed reference counting race condition in context management
 * - Fixed unvalidated user-mode buffer access vulnerabilities
 * - Fixed initialization race condition
 * - Fixed shutdown race with outstanding operations
 * - Fixed TOCTOU in stale context cleanup
 * - Fixed non-atomic flag updates
 * - Implemented proper path matching for sensitive files
 * - Implemented telemetry event dispatch
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "PreSetInfo.h"
#include "FileSystemCallbacks.h"
#include "FileBackupEngine.h"
#include "../../Core/Globals.h"
#include "../../Core/DriverEntry.h"
#include "../../Shared/SharedDefs.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/FileUtils.h"
#include "../../Utilities/StringUtils.h"
#include "../../Communication/CommPort.h"
#include "../../Cache/ScanCache.h"
#include "../../Behavioral/BehaviorEngine.h"
#include "../../Shared/BehaviorTypes.h"
#include "../../Performance/LookasideLists.h"
#include "USBDeviceControl.h"
#include <ntstrsafe.h>

//
// Forward declaration for ScanBridge send API. Cannot include ScanBridge.h
// directly because it has conflicting declarations with CommPort.h.
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendMessage(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_opt_ PLARGE_INTEGER Timeout
);

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Pool tag for PreSetInfo allocations
 */
#define PSI_POOL_TAG                        'iSPS'

/**
 * @brief Maximum file path length for comparison (in bytes)
 */
#define PSI_MAX_PATH_BYTES                  (32768 * sizeof(WCHAR))

/**
 * @brief Maximum allowed buffer allocation for rename info
 */
#define PSI_MAX_RENAME_BUFFER_SIZE          (65535)

/**
 * @brief Ransomware detection: renames per second threshold
 */
#define PSI_RANSOMWARE_RENAME_THRESHOLD     30

/**
 * @brief Ransomware detection: deletes per second threshold
 */
#define PSI_RANSOMWARE_DELETE_THRESHOLD     50

/**
 * @brief Ransomware detection: extension changes threshold
 */
#define PSI_EXTENSION_CHANGE_THRESHOLD      20

/**
 * @brief Data destruction: deletes per minute threshold
 */
#define PSI_DESTRUCTION_DELETE_THRESHOLD    500

/**
 * @brief Credential access: sensitive file hard links threshold
 */
#define PSI_CREDENTIAL_HARDLINK_THRESHOLD   3

/**
 * @brief Time window for rate limiting (100ns units = 1 second)
 */
#define PSI_RATE_LIMIT_WINDOW               10000000LL

/**
 * @brief Suspicious truncation size (file reduced to near zero)
 */
#define PSI_SUSPICIOUS_TRUNCATION_SIZE      4096

/**
 * @brief Maximum tracked processes for behavioral analysis
 */
#define PSI_MAX_TRACKED_PROCESSES           2048

/**
 * @brief Process context expiry time (5 minutes in 100ns)
 */
#define PSI_CONTEXT_EXPIRY_TIME             (5LL * 60 * 10000000)

/**
 * @brief Shutdown wait timeout (10 seconds in 100ns)
 */
#define PSI_SHUTDOWN_WAIT_TIMEOUT           (10LL * 10000000)

/**
 * @brief Shutdown poll interval (10ms in 100ns)
 */
#define PSI_SHUTDOWN_POLL_INTERVAL          (10 * 10000)

// ============================================================================
// SENSITIVE FILE PATTERNS
// ============================================================================

/**
 * @brief Sensitive system file paths for protection matching.
 *
 * MatchMode:
 *   0 = suffix match (path ends with pattern, e.g., \config\SAM)
 *   1 = contains match (path contains pattern, e.g., \drivers\ anywhere in path)
 *
 * Contains-match is used for directory patterns instead of prefix-match because
 * normalized paths from FltGetFileNameInformation start with \Device\HarddiskVolumeN\,
 * so prefix matching against \Windows\ would NEVER succeed.
 */
typedef struct _PSI_SENSITIVE_PATH {
    PCWSTR Pattern;
    UCHAR MatchMode;        // 0 = suffix, 1 = contains
    BOOLEAN BlockDelete;
    BOOLEAN BlockRename;
    BOOLEAN BlockHardLink;
} PSI_SENSITIVE_PATH, *PPSI_SENSITIVE_PATH;

static const PSI_SENSITIVE_PATH g_SensitivePaths[] = {
    // Registry hives - suffix match
    { L"\\Windows\\System32\\config\\SAM",       0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SECURITY",  0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SYSTEM",    0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\SOFTWARE",  0, TRUE, TRUE, TRUE },
    { L"\\Windows\\System32\\config\\DEFAULT",   0, TRUE, TRUE, TRUE },

    // Critical system executables - suffix match
    { L"\\Windows\\System32\\lsass.exe",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\csrss.exe",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\smss.exe",          0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\wininit.exe",       0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\winlogon.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\services.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\ntoskrnl.exe",      0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\hal.dll",           0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\ntdll.dll",         0, TRUE, TRUE, FALSE },
    { L"\\Windows\\System32\\kernel32.dll",      0, TRUE, TRUE, FALSE },

    // Driver directory - contains match (block any file within \drivers\)
    // Contains-match because normalized paths have device prefix that breaks prefix matching
    { L"\\Windows\\System32\\drivers\\",         1, TRUE, TRUE, FALSE },

    // Boot files - contains match
    { L"\\Windows\\Boot\\",                      1, TRUE, TRUE, FALSE },
    { L"\\EFI\\Microsoft\\Boot\\",               1, TRUE, TRUE, FALSE },

    // Boot manager - suffix match
    { L"\\bootmgr",                              0, TRUE, TRUE, FALSE },
    { L"\\BOOTMGR",                              0, TRUE, TRUE, FALSE },

    // NTFS metadata files - suffix match (case sensitive for NTFS internals)
    { L"\\$MFT",                                 0, TRUE, TRUE, FALSE },
    { L"\\$MFTMirr",                             0, TRUE, TRUE, FALSE },
    { L"\\$LogFile",                             0, TRUE, TRUE, FALSE },
    { L"\\$Volume",                              0, TRUE, TRUE, FALSE },
    { L"\\$AttrDef",                             0, TRUE, TRUE, FALSE },
    { L"\\$Bitmap",                              0, TRUE, TRUE, FALSE },
    { L"\\$Boot",                                0, TRUE, TRUE, FALSE },
    { L"\\$BadClus",                             0, TRUE, TRUE, FALSE },
    { L"\\$Secure",                              0, TRUE, TRUE, FALSE },
    { L"\\$UpCase",                              0, TRUE, TRUE, FALSE },
    { L"\\$Extend",                              0, TRUE, TRUE, FALSE },

    // Sentinel
    { NULL, 0, FALSE, FALSE, FALSE }
};

/**
 * @brief Ransomware extension patterns (commonly appended)
 */
static const PCWSTR g_RansomwareExtensions[] = {
    L".encrypted",
    L".locked",
    L".crypto",
    L".crypt",
    L".enc",
    L".locky",
    L".cerber",
    L".zepto",
    L".odin",
    L".thor",
    L".aesir",
    L".zzzzz",
    L".micro",
    L".crypted",
    L".crinf",
    L".r5a",
    L".WNCRY",
    L".wcry",
    L".wncrypt",
    L".wncryt",
    L".petya",
    L".mira",
    L".globe",
    L".purge",
    L".dharma",
    L".wallet",
    L".onion",
    L".ryuk",
    L".sodinokibi",
    L".revil",
    L".lockbit",
    L".conti",
    L".blackcat",
    L".alphv",
    NULL
};

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Per-process SetInfo operation tracking
 */
typedef struct _PSI_PROCESS_CONTEXT {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;

    //
    // Time-windowed counters (per second)
    //
    volatile LONG RecentRenames;
    volatile LONG RecentDeletes;
    volatile LONG RecentExtensionChanges;
    volatile LONG RecentTruncations;
    volatile LONG RecentHardLinks;
    volatile LONG RecentAttributeChanges;
    LARGE_INTEGER WindowStartTime;

    //
    // Total counters
    //
    volatile LONG64 TotalRenames;
    volatile LONG64 TotalDeletes;
    volatile LONG64 TotalExtensionChanges;
    volatile LONG64 TotalTruncations;
    volatile LONG64 TotalHardLinks;
    volatile LONG64 TotalAttributeChanges;

    //
    // Behavioral flags (use InterlockedOr for updates)
    //
    volatile LONG BehaviorFlags;
    volatile LONG SuspicionScore;
    volatile LONG IsRansomwareSuspect;
    volatile LONG IsDestructionSuspect;
    volatile LONG IsCredentialAccessSuspect;
    volatile LONG IsBlocked;

    //
    // Last activity
    //
    LARGE_INTEGER LastActivityTime;
    LARGE_INTEGER FirstActivityTime;

    //
    // Reference counting
    // RefCount includes: 1 for list membership + N for active users
    //
    volatile LONG RefCount;

} PSI_PROCESS_CONTEXT, *PPSI_PROCESS_CONTEXT;

/**
 * @brief Telemetry event structure for user-mode notification
 */
typedef struct _PSI_TELEMETRY_EVENT {
    HANDLE ProcessId;
    FILE_INFORMATION_CLASS InfoClass;
    ULONG BlockReason;
    ULONG SuspicionScore;
    BOOLEAN WasBlocked;
    LARGE_INTEGER Timestamp;
    USHORT FileNameLength;
    WCHAR FileName[1];  // Variable length
} PSI_TELEMETRY_EVENT, *PPSI_TELEMETRY_EVENT;

/**
 * @brief Global PreSetInfo state
 */
typedef struct _PSI_GLOBAL_STATE {
    //
    // Initialization state (use interlocked access)
    //
    volatile LONG InitState;        // 0=uninit, 1=initializing, 2=initialized
    volatile LONG ShuttingDown;

    //
    // Outstanding operation tracking for safe shutdown
    //
    volatile LONG OutstandingOperations;

    //
    // Process context tracking
    //
    LIST_ENTRY ProcessContextList;
    EX_PUSH_LOCK ProcessContextLock;
    volatile LONG ProcessContextCount;

    //
    // Lookaside list for process contexts (centralized if available)
    //
    PLL_LOOKASIDE ProcessContextLookaside;
    NPAGED_LOOKASIDE_LIST ProcessContextLookasideFallback;
    BOOLEAN LookasideInitialized;
    BOOLEAN UseManagedLookaside;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalCalls;
        volatile LONG64 DeleteOperations;
        volatile LONG64 RenameOperations;
        volatile LONG64 HardLinkOperations;
        volatile LONG64 TruncationOperations;
        volatile LONG64 AttributeOperations;
        volatile LONG64 ShortNameOperations;
        volatile LONG64 SelfProtectionBlocks;
        volatile LONG64 RansomwareBlocks;
        volatile LONG64 DestructionBlocks;
        volatile LONG64 CredentialAccessBlocks;
        volatile LONG64 SystemFileBlocks;
        volatile LONG64 ExclusionSkips;
        volatile LONG64 KernelModeSkips;
        volatile LONG64 TelemetryEventsSent;
        volatile LONG64 TelemetryEventsFailed;
        volatile LONG64 CacheInvalidations;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration (atomic reads, protected writes)
    //
    volatile LONG BlockRansomwareBehavior;
    volatile LONG BlockDataDestruction;
    volatile LONG BlockCredentialAccess;
    volatile LONG MonitorAttributeChanges;
    volatile LONG RansomwareRenameThreshold;
    volatile LONG RansomwareDeleteThreshold;
    volatile LONG DestructionDeleteThreshold;

} PSI_GLOBAL_STATE, *PPSI_GLOBAL_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PSI_GLOBAL_STATE g_PsiState = { 0 };

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPSI_PROCESS_CONTEXT
PsipLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
PsipReferenceProcessContext(
    _Inout_ PPSI_PROCESS_CONTEXT Context
    );

static VOID
PsipDereferenceProcessContext(
    _Inout_ PPSI_PROCESS_CONTEXT Context
    );

static VOID
PsipUpdateProcessMetrics(
    _In_ HANDLE ProcessId,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _In_opt_ PCUNICODE_STRING FileName,
    _In_opt_ PCUNICODE_STRING NewFileName,
    _In_ BOOLEAN IsConfirmedDeletion
    );

static BOOLEAN
PsipDetectRansomwareBehavior(
    _In_ PPSI_PROCESS_CONTEXT Context
    );

static BOOLEAN
PsipDetectDataDestruction(
    _In_ PPSI_PROCESS_CONTEXT Context
    );

static BOOLEAN
PsipDetectCredentialAccess(
    _In_ PPSI_PROCESS_CONTEXT Context,
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
PsipIsSensitiveSystemFile(
    _In_ PCUNICODE_STRING FileName,
    _Out_opt_ PBOOLEAN BlockDelete,
    _Out_opt_ PBOOLEAN BlockRename,
    _Out_opt_ PBOOLEAN BlockHardLink
    );

static BOOLEAN
PsipIsRansomwareExtension(
    _In_ PCUNICODE_STRING NewFileName
    );

static BOOLEAN
PsipDetectExtensionChange(
    _In_ PCUNICODE_STRING OriginalName,
    _In_ PCUNICODE_STRING NewName
    );

_Must_inspect_result_
static NTSTATUS
PsipGetRenameDestination(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING NewFileName
    );

static VOID
PsipSendTelemetryEvent(
    _In_ HANDLE ProcessId,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _In_ PCUNICODE_STRING FileName,
    _In_ ULONG BlockReason,
    _In_ ULONG SuspicionScore,
    _In_ BOOLEAN WasBlocked
    );

static VOID
PsipResetTimeWindowedMetrics(
    _Inout_ PPSI_PROCESS_CONTEXT Context
    );

static VOID
PsipCleanupStaleContexts(
    VOID
    );

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
PsipIsInitialized(
    VOID
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * @brief Check if subsystem is fully initialized and not shutting down.
 */
FORCEINLINE
BOOLEAN
PsipIsInitialized(
    VOID
    )
{
    return (g_PsiState.InitState == 2) && (g_PsiState.ShuttingDown == 0);
}

/**
 * @brief Enter an operation (increment outstanding count).
 */
FORCEINLINE
BOOLEAN
PsipEnterOperation(
    VOID
    )
{
    if (!PsipIsInitialized()) {
        return FALSE;
    }
    InterlockedIncrement(&g_PsiState.OutstandingOperations);

    // Double-check after increment
    if (g_PsiState.ShuttingDown) {
        InterlockedDecrement(&g_PsiState.OutstandingOperations);
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Leave an operation (decrement outstanding count).
 */
FORCEINLINE
VOID
PsipLeaveOperation(
    VOID
    )
{
    InterlockedDecrement(&g_PsiState.OutstandingOperations);
}

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize PreSetInfo subsystem.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeInitializePreSetInfo(
    VOID
    )
{
    LONG prevState;

    PAGED_CODE();

    //
    // Atomically transition from uninitialized (0) to initializing (1)
    //
    prevState = InterlockedCompareExchange(&g_PsiState.InitState, 1, 0);

    if (prevState == 2) {
        // Already fully initialized
        return STATUS_ALREADY_REGISTERED;
    }

    if (prevState == 1) {
        // Another thread is currently initializing - wait for it
        while (g_PsiState.InitState == 1) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        return (g_PsiState.InitState == 2) ? STATUS_ALREADY_REGISTERED : STATUS_UNSUCCESSFUL;
    }

    //
    // We won the race - initialize
    //
    g_PsiState.ShuttingDown = 0;
    g_PsiState.OutstandingOperations = 0;
    g_PsiState.ProcessContextCount = 0;
    g_PsiState.LookasideInitialized = FALSE;

    //
    // Initialize process context list
    //
    InitializeListHead(&g_PsiState.ProcessContextList);
    ExInitializePushLock(&g_PsiState.ProcessContextLock);

    //
    // Initialize lookaside list (centralized manager preferred)
    //
    {
        PLL_MANAGER llMgr = ShadowStrikeGetLookasideManager();
        if (llMgr != NULL) {
            NTSTATUS llStatus = LlCreateLookaside(
                llMgr,
                "PreSetInfo",
                PSI_POOL_TAG,
                sizeof(PSI_PROCESS_CONTEXT),
                FALSE,
                &g_PsiState.ProcessContextLookaside
            );
            if (NT_SUCCESS(llStatus)) {
                g_PsiState.UseManagedLookaside = TRUE;
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] PreSetInfo: LlCreateLookaside failed 0x%08X, raw fallback\n",
                           llStatus);
                g_PsiState.ProcessContextLookaside = NULL;
                g_PsiState.UseManagedLookaside = FALSE;
            }
        } else {
            g_PsiState.ProcessContextLookaside = NULL;
            g_PsiState.UseManagedLookaside = FALSE;
        }

        if (!g_PsiState.UseManagedLookaside) {
            ExInitializeNPagedLookasideList(
                &g_PsiState.ProcessContextLookasideFallback,
                NULL, NULL, POOL_NX_ALLOCATION,
                sizeof(PSI_PROCESS_CONTEXT),
                PSI_POOL_TAG, 0
            );
        }
    }
    g_PsiState.LookasideInitialized = TRUE;

    //
    // Set default configuration
    //
    InterlockedExchange(&g_PsiState.BlockRansomwareBehavior, TRUE);
    InterlockedExchange(&g_PsiState.BlockDataDestruction, TRUE);
    InterlockedExchange(&g_PsiState.BlockCredentialAccess, TRUE);
    InterlockedExchange(&g_PsiState.MonitorAttributeChanges, TRUE);
    InterlockedExchange(&g_PsiState.RansomwareRenameThreshold, PSI_RANSOMWARE_RENAME_THRESHOLD);
    InterlockedExchange(&g_PsiState.RansomwareDeleteThreshold, PSI_RANSOMWARE_DELETE_THRESHOLD);
    InterlockedExchange(&g_PsiState.DestructionDeleteThreshold, PSI_DESTRUCTION_DELETE_THRESHOLD);

    //
    // Initialize statistics
    //
    RtlZeroMemory(&g_PsiState.Stats, sizeof(g_PsiState.Stats));
    KeQuerySystemTime(&g_PsiState.Stats.StartTime);

    //
    // Mark as fully initialized
    //
    MemoryBarrier();
    InterlockedExchange(&g_PsiState.InitState, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/PreSetInfo] Subsystem initialized (v2.1.0)\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Cleanup PreSetInfo subsystem.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupPreSetInfo(
    VOID
    )
{
    PLIST_ENTRY entry;
    PPSI_PROCESS_CONTEXT context;

    PAGED_CODE();

    //
    // Check if initialized
    //
    if (g_PsiState.InitState != 2) {
        return;
    }

    //
    // Signal shutdown — PsipEnterOperation will fail after this
    //
    InterlockedExchange(&g_PsiState.ShuttingDown, 1);
    MemoryBarrier();

    //
    // Wait for ALL outstanding operations to complete.
    // CRITICAL: Must use INFINITE wait here. A timed wait that expires and
    // proceeds to delete the lookaside while operations are still outstanding
    // will cause BSOD when those operations later free to the deleted lookaside.
    // PreSetInfo callback is synchronous (FLT_PREOP_SUCCESS_NO_CALLBACK / 
    // FLT_PREOP_COMPLETE — no post-op), so outstanding ops are actively running
    // on other CPUs and will complete in bounded time.
    //
    {
        ULONG spinCount = 0;
        LARGE_INTEGER pollInterval;
        pollInterval.QuadPart = -(10 * 10000); // 10ms

        while (g_PsiState.OutstandingOperations > 0) {
            KeDelayExecutionThread(KernelMode, FALSE, &pollInterval);
            spinCount++;

            //
            // Log periodically so we can diagnose hangs
            //
            if ((spinCount % 1000) == 0) {
                ULONG waitSeconds = (spinCount * 10) / 1000;
                ULONG waitFracMs = (spinCount * 10) % 1000;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/PreSetInfo] Shutdown waiting: %ld outstanding ops (%lu.%lus)\n",
                           g_PsiState.OutstandingOperations,
                           waitSeconds,
                           waitFracMs / 100);
            }
        }
    }

    //
    // Now mark as not initialized to prevent new lookups
    //
    InterlockedExchange(&g_PsiState.InitState, 0);
    MemoryBarrier();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PsiState.ProcessContextLock);

    while (!IsListEmpty(&g_PsiState.ProcessContextList)) {
        entry = RemoveHeadList(&g_PsiState.ProcessContextList);
        context = CONTAINING_RECORD(entry, PSI_PROCESS_CONTEXT, ListEntry);
        InitializeListHead(&context->ListEntry);
        if (g_PsiState.UseManagedLookaside && g_PsiState.ProcessContextLookaside != NULL) {
            LlFree(g_PsiState.ProcessContextLookaside, context);
        } else {
            ExFreeToNPagedLookasideList(&g_PsiState.ProcessContextLookasideFallback, context);
        }
    }
    g_PsiState.ProcessContextCount = 0;

    ExReleasePushLockExclusive(&g_PsiState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (g_PsiState.LookasideInitialized) {
        if (g_PsiState.UseManagedLookaside && g_PsiState.ProcessContextLookaside != NULL) {
            PLL_MANAGER llMgr = ShadowStrikeGetLookasideManager();
            if (llMgr != NULL) {
                LlDestroyLookaside(llMgr, g_PsiState.ProcessContextLookaside);
            }
            g_PsiState.ProcessContextLookaside = NULL;
        } else {
            ExDeleteNPagedLookasideList(&g_PsiState.ProcessContextLookasideFallback);
        }
        g_PsiState.LookasideInitialized = FALSE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/PreSetInfo] Shutdown complete. Stats: "
               "Calls=%lld, Deletes=%lld, Renames=%lld, Blocked=%lld, Telemetry=%lld\n",
               g_PsiState.Stats.TotalCalls,
               g_PsiState.Stats.DeleteOperations,
               g_PsiState.Stats.RenameOperations,
               g_PsiState.Stats.SelfProtectionBlocks +
               g_PsiState.Stats.RansomwareBlocks +
               g_PsiState.Stats.DestructionBlocks,
               g_PsiState.Stats.TelemetryEventsSent);
}

// ============================================================================
// MAIN CALLBACK IMPLEMENTATION
// ============================================================================

/**
 * @brief Pre-operation callback for IRP_MJ_SET_INFORMATION.
 *
 * Enterprise-grade handler for file set information operations including:
 * - Self-protection (delete/rename of AV files)
 * - Ransomware detection (mass rename/delete patterns)
 * - Data destruction prevention
 * - Credential access detection (hard links to SAM/SECURITY)
 * - File attribute manipulation monitoring
 *
 * @param Data              Callback data from filter manager
 * @param FltObjects        Filter objects (volume, instance, file)
 * @param CompletionContext Not used (no post-op callback)
 *
 * @return FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_COMPLETE (blocked)
 *
 * @irql PASSIVE_LEVEL to APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    HANDLE requestorPid;
    FILE_INFORMATION_CLASS infoClass;
    BOOLEAN shouldBlock = FALSE;
    ULONG blockReason = 0;
    UNICODE_STRING newFileName = { 0 };
    BOOLEAN newFileNameAllocated = FALSE;
    PPSI_PROCESS_CONTEXT processContext = NULL;
    BOOLEAN operationEntered = FALSE;
    BOOLEAN isActualDeletion = FALSE;
    BOOLEAN blockDelete = FALSE;
    BOOLEAN blockRename = FALSE;
    BOOLEAN blockHardLink = FALSE;

    //
    // SAL: _Flt_CompletionContext_Outptr_ requires explicit write
    //
    *CompletionContext = NULL;

    //
    // Fast path: Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Fast path: Skip kernel-mode operations
    //
    if (Data->RequestorMode == KernelMode) {
        if (PsipIsInitialized()) {
            InterlockedIncrement64(&g_PsiState.Stats.KernelModeSkips);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get information class
    //
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    //
    // Fast path: Filter only interesting information classes
    //
    switch (infoClass) {
        case FileDispositionInformation:
        case FileDispositionInformationEx:
        case FileRenameInformation:
        case FileRenameInformationEx:
        case FileLinkInformation:
        case FileLinkInformationEx:
        case FileShortNameInformation:
        case FileEndOfFileInformation:
        case FileAllocationInformation:
        case FileBasicInformation:
        case FileValidDataLengthInformation:
            //
            // Proceed with analysis
            //
            break;

        default:
            //
            // Not interesting, skip
            //
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Enter operation tracking (for safe shutdown)
    //
    if (!PsipEnterOperation()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    operationEntered = TRUE;

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_PsiState.Stats.TotalCalls);

    switch (infoClass) {
        case FileDispositionInformation:
        {
            //
            // FSC-3 (CRITICAL): Inspect DeleteFile flag before counting as deletion.
            // DeleteFile=FALSE means "clear deletion mark" (undelete), not delete.
            // Counting undeletes as deletions causes false ransomware alerts.
            //
            PFILE_DISPOSITION_INFORMATION dispInfo =
                (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (Data->Iopb->Parameters.SetFileInformation.Length >=
                sizeof(FILE_DISPOSITION_INFORMATION) &&
                dispInfo != NULL) {
                __try {
                    if (dispInfo->DeleteFile) {
                        InterlockedIncrement64(&g_PsiState.Stats.DeleteOperations);
                        isActualDeletion = TRUE;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Buffer access failed — treat as non-deletion (fail-safe)
                }
            }
            break;
        }
        case FileDispositionInformationEx:
        {
            //
            // FSC-3: For Ex variant, check FILE_DISPOSITION_DELETE flag (bit 0).
            // Also detect POSIX semantics (bit 1).
            //
            PFILE_DISPOSITION_INFORMATION_EX dispInfoEx =
                (PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (Data->Iopb->Parameters.SetFileInformation.Length >=
                sizeof(FILE_DISPOSITION_INFORMATION_EX) &&
                dispInfoEx != NULL) {
                __try {
                    if (dispInfoEx->Flags & FILE_DISPOSITION_DELETE) {
                        InterlockedIncrement64(&g_PsiState.Stats.DeleteOperations);
                        isActualDeletion = TRUE;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Buffer access failed — treat as non-deletion (fail-safe)
                }
            }
            break;
        }
        case FileRenameInformation:
        case FileRenameInformationEx:
            InterlockedIncrement64(&g_PsiState.Stats.RenameOperations);
            break;
        case FileLinkInformation:
        case FileLinkInformationEx:
            InterlockedIncrement64(&g_PsiState.Stats.HardLinkOperations);
            break;
        case FileShortNameInformation:
            InterlockedIncrement64(&g_PsiState.Stats.ShortNameOperations);
            break;
        case FileEndOfFileInformation:
        case FileAllocationInformation:
        case FileValidDataLengthInformation:
            InterlockedIncrement64(&g_PsiState.Stats.TruncationOperations);
            break;
        case FileBasicInformation:
            InterlockedIncrement64(&g_PsiState.Stats.AttributeOperations);
            break;
        default:
            break;
    }

    requestorPid = PsGetCurrentProcessId();

    //
    // Check process exclusion
    //
    if (ShadowStrikeIsProcessTrusted(requestorPid) ||
        ShadowStrikeIsProcessExcluded(requestorPid, NULL)) {
        InterlockedIncrement64(&g_PsiState.Stats.ExclusionSkips);
        goto AllowOperation;
    }

    //
    // Get file name information
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
        );

    if (!NT_SUCCESS(status)) {
        goto AllowOperation;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        goto AllowOperation;
    }

    //
    // Check path exclusion
    //
    if (ShadowStrikeIsPathExcluded(&nameInfo->Name, NULL)) {
        InterlockedIncrement64(&g_PsiState.Stats.ExclusionSkips);
        goto AllowOperation;
    }

    //
    // USB Device Control: Block rename/delete on read-only removable volumes
    //
    if (UdcIsSetInfoBlocked(FltObjects)) {
        shouldBlock = TRUE;

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/PreSetInfo] BLOCKED: USB read-only policy denied set-info: %wZ (PID=%lu)\n",
            &nameInfo->Name,
            HandleToULong(requestorPid)
            );

        goto AllowOperation;
    }

    //
    // For rename/link operations, get the destination path
    //
    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx ||
        infoClass == FileLinkInformation ||
        infoClass == FileLinkInformationEx) {

        status = PsipGetRenameDestination(Data, &newFileName);
        if (NT_SUCCESS(status)) {
            newFileNameAllocated = TRUE;
        }
    }

    //
    // ========================================================================
    // SELF-PROTECTION CHECK
    // ========================================================================
    //
    if (g_DriverData.Config.SelfProtectionEnabled) {
        BOOLEAN isDeleteOrRename = FALSE;

        switch (infoClass) {
            case FileDispositionInformation:
            case FileDispositionInformationEx:
            case FileRenameInformation:
            case FileRenameInformationEx:
            case FileLinkInformation:
            case FileLinkInformationEx:
                isDeleteOrRename = TRUE;
                break;
            default:
                break;
        }

        if (isDeleteOrRename) {
            if (ShadowStrikeShouldBlockFileAccess(
                    &nameInfo->Name,
                    0,
                    requestorPid,
                    TRUE)) {

                shouldBlock = TRUE;
                blockReason = PSI_BEHAVIOR_AV_TAMPERING;
                InterlockedIncrement64(&g_PsiState.Stats.SelfProtectionBlocks);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/PreSetInfo] BLOCKED: Self-protection (source) "
                           "PID=%lu, File=%wZ, Class=%d\n",
                           HandleToULong(requestorPid),
                           &nameInfo->Name,
                           infoClass);

                goto CompleteOperation;
            }

            //
            // FP-C1 FIX: Also check DESTINATION path for rename/hardlink.
            // Without this, an attacker can overwrite a protected file by
            // renaming an unprotected file to the protected path.
            //
            if (newFileNameAllocated && newFileName.Buffer != NULL && newFileName.Length > 0) {
                if (ShadowStrikeShouldBlockFileAccess(
                        &newFileName,
                        0,
                        requestorPid,
                        TRUE)) {

                    shouldBlock = TRUE;
                    blockReason = PSI_BEHAVIOR_AV_TAMPERING;
                    InterlockedIncrement64(&g_PsiState.Stats.SelfProtectionBlocks);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike/PreSetInfo] BLOCKED: Self-protection (dest) "
                               "PID=%lu, Source=%wZ, Dest=%wZ, Class=%d\n",
                               HandleToULong(requestorPid),
                               &nameInfo->Name,
                               &newFileName,
                               infoClass);

                    goto CompleteOperation;
                }
            }
        }
    }

    //
    // ========================================================================
    // SENSITIVE SYSTEM FILE CHECK
    // ========================================================================
    //
    if (PsipIsSensitiveSystemFile(&nameInfo->Name, &blockDelete, &blockRename, &blockHardLink)) {
        BOOLEAN shouldBlockThis = FALSE;

        switch (infoClass) {
            case FileDispositionInformation:
            case FileDispositionInformationEx:
                shouldBlockThis = blockDelete;
                break;
            case FileRenameInformation:
            case FileRenameInformationEx:
                shouldBlockThis = blockRename;
                break;
            case FileLinkInformation:
            case FileLinkInformationEx:
                shouldBlockThis = blockHardLink;
                break;
            default:
                break;
        }

        if (shouldBlockThis) {
            shouldBlock = TRUE;
            blockReason = PSI_BEHAVIOR_SYSTEM_FILE_ACCESS;
            InterlockedIncrement64(&g_PsiState.Stats.SystemFileBlocks);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/PreSetInfo] BLOCKED: Sensitive file "
                       "PID=%lu, File=%wZ, Class=%d\n",
                       HandleToULong(requestorPid),
                       &nameInfo->Name,
                       infoClass);

            goto CompleteOperation;
        }
    }

    //
    // ========================================================================
    // CREDENTIAL ACCESS CHECK (HARD LINK TO SAM/SECURITY)
    // ========================================================================
    //
    if ((infoClass == FileLinkInformation || infoClass == FileLinkInformationEx) &&
        g_PsiState.BlockCredentialAccess) {

        //
        // Check if target is a credential file (already checked above, but re-check for hard link)
        //
        if (blockHardLink) {
            processContext = PsipLookupProcessContext(requestorPid, TRUE);
            if (processContext != NULL) {
                InterlockedIncrement(&processContext->RecentHardLinks);
                InterlockedIncrement64(&processContext->TotalHardLinks);

                if (PsipDetectCredentialAccess(processContext, &nameInfo->Name)) {
                    shouldBlock = TRUE;
                    blockReason = PSI_BEHAVIOR_CREDENTIAL_ACCESS;
                    InterlockedIncrement64(&g_PsiState.Stats.CredentialAccessBlocks);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike/PreSetInfo] BLOCKED: Credential access "
                               "PID=%lu, File=%wZ\n",
                               HandleToULong(requestorPid),
                               &nameInfo->Name);
                }

                PsipDereferenceProcessContext(processContext);
                processContext = NULL;
            }

            if (shouldBlock) {
                goto CompleteOperation;
            }
        }
    }

    //
    // ========================================================================
    // RANSOMWARE ROLLBACK — Backup file before rename/delete
    // ========================================================================
    //
    if (infoClass == FileDispositionInformation ||
        infoClass == FileDispositionInformationEx ||
        infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx) {

        FBE_OPERATION_TYPE fbeOpType;

        if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
            fbeOpType = FbeOp_Rename;
        } else {
            fbeOpType = FbeOp_Delete;
        }

        FbePreSetInfoBackup(Data, FltObjects, &nameInfo->Name, fbeOpType);
    }

    //
    // ========================================================================
    // SCAN CACHE INVALIDATION
    // ========================================================================
    // Rename/delete/truncation changes file content or removes the file.
    // Stale cached scan verdicts must be evicted to prevent bypass.
    //
    if (FltObjects->FileObject != NULL) {
        SHADOWSTRIKE_CACHE_KEY cacheKey;
        NTSTATUS cacheStatus;

        cacheStatus = ShadowStrikeCacheBuildKey(FltObjects, &cacheKey);
        if (NT_SUCCESS(cacheStatus)) {
            if (ShadowStrikeCacheRemove(&cacheKey)) {
                InterlockedIncrement64(&g_PsiState.Stats.CacheInvalidations);
            }
        }
    }

    //
    // ========================================================================
    // BEHAVIORAL ANALYSIS
    // ========================================================================
    //
    if (PsipIsInitialized()) {
        //
        // Update process metrics
        //
        PsipUpdateProcessMetrics(
            requestorPid,
            infoClass,
            &nameInfo->Name,
            newFileNameAllocated ? &newFileName : NULL,
            isActualDeletion
            );

        //
        // Check for ransomware behavior
        //
        if (g_PsiState.BlockRansomwareBehavior) {
            processContext = PsipLookupProcessContext(requestorPid, FALSE);
            if (processContext != NULL) {
                if (PsipDetectRansomwareBehavior(processContext)) {
                    //
                    // Only block deletes and renames from ransomware suspects
                    //
                    if (infoClass == FileDispositionInformation ||
                        infoClass == FileDispositionInformationEx ||
                        infoClass == FileRenameInformation ||
                        infoClass == FileRenameInformationEx) {

                        shouldBlock = TRUE;
                        blockReason = PSI_BEHAVIOR_MASS_RENAME | PSI_BEHAVIOR_MASS_DELETE;
                        InterlockedIncrement64(&g_PsiState.Stats.RansomwareBlocks);

                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[ShadowStrike/PreSetInfo] BLOCKED: Ransomware behavior "
                                   "PID=%lu, File=%wZ, Score=%ld\n",
                                   HandleToULong(requestorPid),
                                   &nameInfo->Name,
                                   processContext->SuspicionScore);
                    }
                }

                PsipDereferenceProcessContext(processContext);
                processContext = NULL;
            }
        }

        if (shouldBlock) {
            goto CompleteOperation;
        }

        //
        // Check for data destruction behavior
        //
        if (g_PsiState.BlockDataDestruction) {
            processContext = PsipLookupProcessContext(requestorPid, FALSE);
            if (processContext != NULL) {
                if (PsipDetectDataDestruction(processContext)) {
                    if (infoClass == FileDispositionInformation ||
                        infoClass == FileDispositionInformationEx) {

                        shouldBlock = TRUE;
                        blockReason = PSI_BEHAVIOR_MASS_DELETE;
                        InterlockedIncrement64(&g_PsiState.Stats.DestructionBlocks);

                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[ShadowStrike/PreSetInfo] BLOCKED: Data destruction "
                                   "PID=%lu, File=%wZ, Deletes=%lld\n",
                                   HandleToULong(requestorPid),
                                   &nameInfo->Name,
                                   processContext->TotalDeletes);
                    }
                }

                PsipDereferenceProcessContext(processContext);
                processContext = NULL;
            }
        }

        if (shouldBlock) {
            goto CompleteOperation;
        }

        //
        // Check for ransomware extension on rename
        //
        if (newFileNameAllocated && newFileName.Length > 0) {
            if (PsipIsRansomwareExtension(&newFileName)) {
                processContext = PsipLookupProcessContext(requestorPid, TRUE);
                if (processContext != NULL) {
                    InterlockedOr(&processContext->BehaviorFlags, PSI_BEHAVIOR_EXTENSION_CHANGE);
                    InterlockedIncrement(&processContext->RecentExtensionChanges);
                    InterlockedIncrement64(&processContext->TotalExtensionChanges);

                    //
                    // High suspicion for ransomware extension
                    //
                    if (processContext->RecentExtensionChanges > 5) {
                        shouldBlock = TRUE;
                        blockReason = PSI_BEHAVIOR_EXTENSION_CHANGE;
                        InterlockedIncrement64(&g_PsiState.Stats.RansomwareBlocks);

                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[ShadowStrike/PreSetInfo] BLOCKED: Ransomware extension "
                                   "PID=%lu, File=%wZ -> %wZ\n",
                                   HandleToULong(requestorPid),
                                   &nameInfo->Name,
                                   &newFileName);
                    }

                    PsipDereferenceProcessContext(processContext);
                    processContext = NULL;
                }
            }
        }
    }

CompleteOperation:
    //
    // Send telemetry for blocked or suspicious operations
    //
    if (shouldBlock || blockReason != 0) {
        ULONG score = 0;
        processContext = PsipLookupProcessContext(requestorPid, FALSE);
        if (processContext != NULL) {
            score = (ULONG)processContext->SuspicionScore;
            PsipDereferenceProcessContext(processContext);
        }

        BeEngineSubmitEvent(
            (blockReason & PSI_BEHAVIOR_EXTENSION_CHANGE)
                ? BehaviorEvent_RansomwareBehavior
                : (blockReason & PSI_BEHAVIOR_MASS_DELETE)
                    ? BehaviorEvent_DataDestruction
                    : BehaviorEvent_RansomwareBehavior,
            BehaviorCategory_Impact,
            HandleToULong(requestorPid),
            NULL, 0,
            score,
            shouldBlock,
            NULL
            );

        PsipSendTelemetryEvent(
            requestorPid,
            infoClass,
            &nameInfo->Name,
            blockReason,
            score,
            shouldBlock
            );
    }

AllowOperation:
    //
    // Cleanup
    //
    if (newFileNameAllocated && newFileName.Buffer != NULL) {
        ExFreePoolWithTag(newFileName.Buffer, PSI_POOL_TAG);
        newFileName.Buffer = NULL;
    }

    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    if (operationEntered) {
        PsipLeaveOperation();
    }

    //
    // Block or allow
    //
    if (shouldBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        SHADOWSTRIKE_INC_STAT(FilesBlocked);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Lookup or create a process context.
 *
 * Thread-safe lookup with optional creation. Returns with reference held.
 *
 * @param ProcessId       Process ID to lookup.
 * @param CreateIfNotFound Create new context if not found.
 *
 * @return Context with reference held, or NULL.
 */
static PPSI_PROCESS_CONTEXT
PsipLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    PLIST_ENTRY entry;
    PPSI_PROCESS_CONTEXT context = NULL;
    PPSI_PROCESS_CONTEXT newContext = NULL;
    LARGE_INTEGER currentTime;

    if (!PsipIsInitialized()) {
        return NULL;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Search existing contexts (shared lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PsiState.ProcessContextLock);

    for (entry = g_PsiState.ProcessContextList.Flink;
         entry != &g_PsiState.ProcessContextList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, PSI_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            //
            // Found - add reference while still under lock
            //
            InterlockedIncrement(&context->RefCount);

            //
            // Check if time window needs reset
            //
            if ((currentTime.QuadPart - context->WindowStartTime.QuadPart) > PSI_RATE_LIMIT_WINDOW) {
                PsipResetTimeWindowedMetrics(context);
            }

            ExReleasePushLockShared(&g_PsiState.ProcessContextLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&g_PsiState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Check max tracked processes
    //
    if (g_PsiState.ProcessContextCount >= PSI_MAX_TRACKED_PROCESSES) {
        PsipCleanupStaleContexts();
    }

    //
    // Pre-allocate new context outside the lock
    //
    if (g_PsiState.UseManagedLookaside && g_PsiState.ProcessContextLookaside != NULL) {
        newContext = (PPSI_PROCESS_CONTEXT)LlAllocate(g_PsiState.ProcessContextLookaside);
    } else {
        newContext = (PPSI_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
            &g_PsiState.ProcessContextLookasideFallback
        );
    }

    if (newContext == NULL) {
        return NULL;
    }

    RtlZeroMemory(newContext, sizeof(PSI_PROCESS_CONTEXT));
    newContext->ProcessId = ProcessId;
    newContext->RefCount = 2;  // 1 for list + 1 for caller
    newContext->WindowStartTime = currentTime;
    newContext->FirstActivityTime = currentTime;
    newContext->LastActivityTime = currentTime;
    InitializeListHead(&newContext->ListEntry);

    //
    // Insert into list (exclusive lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PsiState.ProcessContextLock);

    //
    // Re-check for race condition - another thread may have created it
    //
    for (entry = g_PsiState.ProcessContextList.Flink;
         entry != &g_PsiState.ProcessContextList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, PSI_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            //
            // Found - someone else created it, use theirs
            //
            InterlockedIncrement(&context->RefCount);
            ExReleasePushLockExclusive(&g_PsiState.ProcessContextLock);
            KeLeaveCriticalRegion();

            // Free our pre-allocated context
            if (g_PsiState.UseManagedLookaside && g_PsiState.ProcessContextLookaside != NULL) {
                LlFree(g_PsiState.ProcessContextLookaside, newContext);
            } else {
                ExFreeToNPagedLookasideList(&g_PsiState.ProcessContextLookasideFallback, newContext);
            }
            return context;
        }
    }

    //
    // Insert our new context
    //
    InsertTailList(&g_PsiState.ProcessContextList, &newContext->ListEntry);
    InterlockedIncrement(&g_PsiState.ProcessContextCount);

    ExReleasePushLockExclusive(&g_PsiState.ProcessContextLock);
    KeLeaveCriticalRegion();

    return newContext;
}

/**
 * @brief Add a reference to a process context.
 */
static VOID
PsipReferenceProcessContext(
    _Inout_ PPSI_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}

/**
 * @brief Release a reference to a process context.
 *
 * FIXED: Two-phase approach — interlocked decrement first (fast path),
 * only acquire exclusive lock if refcount reaches zero (slow path).
 * This avoids serializing all derefs through a single exclusive lock.
 */
static VOID
PsipDereferenceProcessContext(
    _Inout_ PPSI_PROCESS_CONTEXT Context
    )
{
    LONG newRefCount;
    BOOLEAN shouldFree = FALSE;

    //
    // Fast path: decrement without lock. If result > 0, we're done.
    //
    newRefCount = InterlockedDecrement(&Context->RefCount);

    if (newRefCount > 0) {
        return;
    }

    if (newRefCount < 0) {
        //
        // BUG: Over-release detected — attempt recovery
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/PreSetInfo] BUG: RefCount went negative for PID=%lu\n",
                   HandleToULong(Context->ProcessId));
        InterlockedExchange(&Context->RefCount, 0);
        return;
    }

    //
    // Slow path: RefCount reached 0. Take exclusive lock and verify
    // no one incremented it back while we were acquiring the lock.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PsiState.ProcessContextLock);

    if (Context->RefCount == 0) {
        //
        // Still zero under lock — safe to remove from list
        //
        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_PsiState.ProcessContextCount);
        }
        shouldFree = TRUE;
    }
    // else: someone re-referenced it while we waited for the lock — leave it

    ExReleasePushLockExclusive(&g_PsiState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (shouldFree) {
        if (g_PsiState.UseManagedLookaside && g_PsiState.ProcessContextLookaside != NULL) {
            LlFree(g_PsiState.ProcessContextLookaside, Context);
        } else {
            ExFreeToNPagedLookasideList(&g_PsiState.ProcessContextLookasideFallback, Context);
        }
    }
}

/**
 * @brief Reset time-windowed metrics when window expires.
 */
static VOID
PsipResetTimeWindowedMetrics(
    _Inout_ PPSI_PROCESS_CONTEXT Context
    )
{
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);

    InterlockedExchange(&Context->RecentRenames, 0);
    InterlockedExchange(&Context->RecentDeletes, 0);
    InterlockedExchange(&Context->RecentExtensionChanges, 0);
    InterlockedExchange(&Context->RecentTruncations, 0);
    InterlockedExchange(&Context->RecentHardLinks, 0);
    InterlockedExchange(&Context->RecentAttributeChanges, 0);
    Context->WindowStartTime = currentTime;
}

/**
 * @brief Cleanup stale process contexts.
 *
 * FIXED: Uses InterlockedCompareExchange to atomically claim contexts
 * for removal, preventing TOCTOU race conditions.
 */
static VOID
PsipCleanupStaleContexts(
    VOID
    )
{
    PLIST_ENTRY entry, next;
    PPSI_PROCESS_CONTEXT context;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER expiryThreshold;
    LIST_ENTRY staleList;
    LONG prevRefCount;

    InitializeListHead(&staleList);

    KeQuerySystemTime(&currentTime);
    expiryThreshold.QuadPart = currentTime.QuadPart - PSI_CONTEXT_EXPIRY_TIME;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PsiState.ProcessContextLock);

    for (entry = g_PsiState.ProcessContextList.Flink;
         entry != &g_PsiState.ProcessContextList;
         entry = next) {

        next = entry->Flink;
        context = CONTAINING_RECORD(entry, PSI_PROCESS_CONTEXT, ListEntry);

        //
        // Check if context is stale
        //
        if (context->LastActivityTime.QuadPart < expiryThreshold.QuadPart) {
            //
            // FIXED: Atomically try to claim the context for removal.
            // Only remove if RefCount is exactly 1 (list reference only).
            //
            prevRefCount = InterlockedCompareExchange(&context->RefCount, 0, 1);

            if (prevRefCount == 1) {
                // Successfully claimed - remove from list
                RemoveEntryList(&context->ListEntry);
                InitializeListHead(&context->ListEntry);
                InterlockedDecrement(&g_PsiState.ProcessContextCount);
                InsertTailList(&staleList, &context->ListEntry);
            }
            // If prevRefCount != 1, someone else has a reference, skip it
        }
    }

    ExReleasePushLockExclusive(&g_PsiState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Free stale contexts outside lock
    //
    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        context = CONTAINING_RECORD(entry, PSI_PROCESS_CONTEXT, ListEntry);
        if (g_PsiState.UseManagedLookaside && g_PsiState.ProcessContextLookaside != NULL) {
            LlFree(g_PsiState.ProcessContextLookaside, context);
        } else {
            ExFreeToNPagedLookasideList(&g_PsiState.ProcessContextLookasideFallback, context);
        }
    }
}

// ============================================================================
// BEHAVIORAL ANALYSIS
// ============================================================================

static VOID
PsipUpdateProcessMetrics(
    _In_ HANDLE ProcessId,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _In_opt_ PCUNICODE_STRING FileName,
    _In_opt_ PCUNICODE_STRING NewFileName,
    _In_ BOOLEAN IsConfirmedDeletion
    )
{
    PPSI_PROCESS_CONTEXT context;
    LARGE_INTEGER currentTime;

    context = PsipLookupProcessContext(ProcessId, TRUE);
    if (context == NULL) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    context->LastActivityTime = currentTime;

    //
    // Update counters based on operation type
    //
    switch (InfoClass) {
        case FileDispositionInformation:
        case FileDispositionInformationEx:
            //
            // FSC-3: Only count confirmed deletions (DeleteFile=TRUE / FILE_DISPOSITION_DELETE).
            // Undelete operations (clearing delete flag) must NOT inflate ransomware counters.
            //
            if (IsConfirmedDeletion) {
                InterlockedIncrement(&context->RecentDeletes);
                InterlockedIncrement64(&context->TotalDeletes);
            }
            break;

        case FileRenameInformation:
        case FileRenameInformationEx:
            InterlockedIncrement(&context->RecentRenames);
            InterlockedIncrement64(&context->TotalRenames);

            //
            // Check for extension change
            //
            if (FileName != NULL && NewFileName != NULL) {
                if (PsipDetectExtensionChange(FileName, NewFileName)) {
                    InterlockedIncrement(&context->RecentExtensionChanges);
                    InterlockedIncrement64(&context->TotalExtensionChanges);
                    InterlockedOr(&context->BehaviorFlags, PSI_BEHAVIOR_EXTENSION_CHANGE);
                }
            }
            break;

        case FileLinkInformation:
        case FileLinkInformationEx:
            InterlockedIncrement(&context->RecentHardLinks);
            InterlockedIncrement64(&context->TotalHardLinks);
            break;

        case FileEndOfFileInformation:
        case FileAllocationInformation:
        case FileValidDataLengthInformation:
            InterlockedIncrement(&context->RecentTruncations);
            InterlockedIncrement64(&context->TotalTruncations);
            break;

        case FileBasicInformation:
            InterlockedIncrement(&context->RecentAttributeChanges);
            InterlockedIncrement64(&context->TotalAttributeChanges);
            break;

        default:
            break;
    }

    PsipDereferenceProcessContext(context);
}

static BOOLEAN
PsipDetectRansomwareBehavior(
    _In_ PPSI_PROCESS_CONTEXT Context
    )
{
    LONG score = 0;
    LONG renameThreshold = g_PsiState.RansomwareRenameThreshold;
    LONG deleteThreshold = g_PsiState.RansomwareDeleteThreshold;

    //
    // Check for mass rename pattern
    //
    if (Context->RecentRenames > renameThreshold) {
        score += 40;
        InterlockedOr(&Context->BehaviorFlags, PSI_BEHAVIOR_MASS_RENAME);
    }

    //
    // Check for mass delete pattern
    //
    if (Context->RecentDeletes > deleteThreshold) {
        score += 35;
        InterlockedOr(&Context->BehaviorFlags, PSI_BEHAVIOR_MASS_DELETE);
    }

    //
    // Check for extension changes
    //
    if (Context->RecentExtensionChanges > PSI_EXTENSION_CHANGE_THRESHOLD) {
        score += 30;
        InterlockedOr(&Context->BehaviorFlags, PSI_BEHAVIOR_EXTENSION_CHANGE);
    }

    //
    // Historical patterns add to score
    //
    if (Context->TotalRenames > 1000) {
        score += 15;
    }

    if (Context->TotalExtensionChanges > 100) {
        score += 20;
    }

    //
    // Combined rename + extension change is very suspicious
    //
    if ((Context->BehaviorFlags & PSI_BEHAVIOR_MASS_RENAME) &&
        (Context->BehaviorFlags & PSI_BEHAVIOR_EXTENSION_CHANGE)) {
        score += 25;
    }

    InterlockedExchange(&Context->SuspicionScore, score);

    if (score >= 70) {
        InterlockedExchange(&Context->IsRansomwareSuspect, TRUE);
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
PsipDetectDataDestruction(
    _In_ PPSI_PROCESS_CONTEXT Context
    )
{
    LONG threshold = g_PsiState.DestructionDeleteThreshold;

    //
    // Mass deletion pattern
    //
    if (Context->TotalDeletes > threshold) {
        InterlockedExchange(&Context->IsDestructionSuspect, TRUE);
        InterlockedOr(&Context->BehaviorFlags, PSI_BEHAVIOR_MASS_DELETE);
        return TRUE;
    }

    //
    // High rate of deletion in time window
    //
    if (Context->RecentDeletes > (threshold / 10)) {
        InterlockedExchange(&Context->IsDestructionSuspect, TRUE);
        InterlockedOr(&Context->BehaviorFlags, PSI_BEHAVIOR_MASS_DELETE);
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
PsipDetectCredentialAccess(
    _In_ PPSI_PROCESS_CONTEXT Context,
    _In_ PCUNICODE_STRING FileName
    )
{
    UNREFERENCED_PARAMETER(FileName);

    //
    // Multiple hard links to sensitive files
    //
    if (Context->TotalHardLinks >= PSI_CREDENTIAL_HARDLINK_THRESHOLD) {
        InterlockedExchange(&Context->IsCredentialAccessSuspect, TRUE);
        InterlockedOr(&Context->BehaviorFlags, PSI_BEHAVIOR_CREDENTIAL_ACCESS);
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PATTERN DETECTION HELPERS
// ============================================================================

/**
 * @brief Check if a file path matches sensitive system files.
 *
 * FIXED: Replaced broken prefix-match with contains-match for directory
 * patterns. Normalized paths start with \Device\HarddiskVolumeN\ so
 * prefix matching against \Windows\ never succeeded — leaving drivers,
 * boot files, and EFI partition completely unprotected.
 *
 * MatchMode 0 (suffix): path ENDS with pattern (boundary-validated)
 * MatchMode 1 (contains): pattern appears ANYWHERE in path (case-insensitive)
 */
static BOOLEAN
PsipIsSensitiveSystemFile(
    _In_ PCUNICODE_STRING FileName,
    _Out_opt_ PBOOLEAN BlockDelete,
    _Out_opt_ PBOOLEAN BlockRename,
    _Out_opt_ PBOOLEAN BlockHardLink
    )
{
    ULONG i;
    UNICODE_STRING pattern;
    USHORT patternChars;
    USHORT fileChars;
    PWCHAR fileStart;
    LONG compareResult;

    if (BlockDelete) *BlockDelete = FALSE;
    if (BlockRename) *BlockRename = FALSE;
    if (BlockHardLink) *BlockHardLink = FALSE;

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {
        return FALSE;
    }

    fileChars = FileName->Length / sizeof(WCHAR);

    for (i = 0; g_SensitivePaths[i].Pattern != NULL; i++) {
        RtlInitUnicodeString(&pattern, g_SensitivePaths[i].Pattern);
        patternChars = pattern.Length / sizeof(WCHAR);

        if (patternChars > fileChars) {
            continue;
        }

        if (g_SensitivePaths[i].MatchMode == 1) {
            //
            // Contains match: scan for pattern anywhere within the path.
            // Slide a window of pattern.Length across FileName and compare
            // case-insensitively at each path-separator boundary.
            //
            USHORT maxOffset = fileChars - patternChars;
            USHORT offset;
            BOOLEAN found = FALSE;

            for (offset = 0; offset <= maxOffset; offset++) {
                //
                // Only compare at path-separator boundaries to prevent
                // false positives (e.g., "C:\notWindows\System32\drivers\")
                //
                if (offset > 0 && FileName->Buffer[offset - 1] != L'\\' &&
                    FileName->Buffer[offset - 1] != L':') {
                    continue;
                }

                UNICODE_STRING candidate;
                candidate.Buffer = FileName->Buffer + offset;
                candidate.Length = pattern.Length;
                candidate.MaximumLength = pattern.Length;

                if (RtlCompareUnicodeString(&candidate, &pattern, TRUE) == 0) {
                    found = TRUE;
                    break;
                }
            }

            if (found) {
                if (BlockDelete) *BlockDelete = g_SensitivePaths[i].BlockDelete;
                if (BlockRename) *BlockRename = g_SensitivePaths[i].BlockRename;
                if (BlockHardLink) *BlockHardLink = g_SensitivePaths[i].BlockHardLink;
                return TRUE;
            }
        }
        else {
            //
            // Suffix match: check if file path ENDS with pattern
            // This handles exact file patterns like "\Windows\System32\config\SAM"
            //
            fileStart = FileName->Buffer + (fileChars - patternChars);

            UNICODE_STRING fileSuffix;
            fileSuffix.Buffer = fileStart;
            fileSuffix.Length = pattern.Length;
            fileSuffix.MaximumLength = pattern.Length;

            compareResult = RtlCompareUnicodeString(&fileSuffix, &pattern, TRUE);
            if (compareResult == 0) {
                //
                // Boundary validation: ensure the match is at a path boundary.
                // If the pattern starts with '\', the leading backslash IS the
                // boundary marker — no further check needed. Otherwise, the
                // character before the match must be '\' or ':' (or start of path).
                //
                BOOLEAN isBoundary = FALSE;

                if (fileStart == FileName->Buffer) {
                    isBoundary = TRUE;
                } else if (pattern.Buffer[0] == L'\\') {
                    isBoundary = TRUE;
                } else if (*(fileStart - 1) == L'\\' || *(fileStart - 1) == L':') {
                    isBoundary = TRUE;
                }

                if (isBoundary) {
                    if (BlockDelete) *BlockDelete = g_SensitivePaths[i].BlockDelete;
                    if (BlockRename) *BlockRename = g_SensitivePaths[i].BlockRename;
                    if (BlockHardLink) *BlockHardLink = g_SensitivePaths[i].BlockHardLink;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static BOOLEAN
PsipIsRansomwareExtension(
    _In_ PCUNICODE_STRING NewFileName
    )
{
    ULONG i;
    UNICODE_STRING extension;
    UNICODE_STRING fileExt;
    USHORT j;

    if (NewFileName == NULL || NewFileName->Length == 0 || NewFileName->Buffer == NULL) {
        return FALSE;
    }

    //
    // Extract extension from new file name
    //
    fileExt.Buffer = NULL;
    fileExt.Length = 0;
    fileExt.MaximumLength = 0;

    for (j = NewFileName->Length / sizeof(WCHAR); j > 0; j--) {
        if (NewFileName->Buffer[j - 1] == L'.') {
            fileExt.Buffer = &NewFileName->Buffer[j - 1];
            fileExt.Length = NewFileName->Length - ((j - 1) * sizeof(WCHAR));
            fileExt.MaximumLength = fileExt.Length;
            break;
        }
        if (NewFileName->Buffer[j - 1] == L'\\') {
            break;  // No extension found
        }
    }

    if (fileExt.Length == 0) {
        return FALSE;
    }

    //
    // Check against known ransomware extensions
    //
    for (i = 0; g_RansomwareExtensions[i] != NULL; i++) {
        RtlInitUnicodeString(&extension, g_RansomwareExtensions[i]);

        if (RtlEqualUnicodeString(&fileExt, &extension, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PsipDetectExtensionChange(
    _In_ PCUNICODE_STRING OriginalName,
    _In_ PCUNICODE_STRING NewName
    )
{
    UNICODE_STRING origExt = { 0 };
    UNICODE_STRING newExt = { 0 };
    USHORT i;

    if (OriginalName == NULL || NewName == NULL ||
        OriginalName->Buffer == NULL || NewName->Buffer == NULL) {
        return FALSE;
    }

    //
    // Extract original extension
    //
    for (i = OriginalName->Length / sizeof(WCHAR); i > 0; i--) {
        if (OriginalName->Buffer[i - 1] == L'.') {
            origExt.Buffer = &OriginalName->Buffer[i - 1];
            origExt.Length = OriginalName->Length - ((i - 1) * sizeof(WCHAR));
            origExt.MaximumLength = origExt.Length;
            break;
        }
        if (OriginalName->Buffer[i - 1] == L'\\') {
            break;
        }
    }

    //
    // Extract new extension
    //
    for (i = NewName->Length / sizeof(WCHAR); i > 0; i--) {
        if (NewName->Buffer[i - 1] == L'.') {
            newExt.Buffer = &NewName->Buffer[i - 1];
            newExt.Length = NewName->Length - ((i - 1) * sizeof(WCHAR));
            newExt.MaximumLength = newExt.Length;
            break;
        }
        if (NewName->Buffer[i - 1] == L'\\') {
            break;
        }
    }

    //
    // Extension added (no original, has new)
    //
    if (origExt.Length == 0 && newExt.Length > 0) {
        return TRUE;
    }

    //
    // Extension changed
    //
    if (origExt.Length > 0 && newExt.Length > 0) {
        if (!RtlEqualUnicodeString(&origExt, &newExt, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Extract rename/link destination from SetInformation buffer.
 *
 * FIXED: Proper user buffer validation with:
 * - Buffer length validation
 * - Integer overflow protection
 * - try/except for user buffer access
 * - USHORT truncation protection
 */
_Must_inspect_result_
static NTSTATUS
PsipGetRenameDestination(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING NewFileName
    )
{
    PFILE_RENAME_INFORMATION renameInfo;
    ULONG infoBufferLength;
    ULONG fileNameLength;
    ULONG bufferLength;
    ULONG maxFileNameLength;
    PWCHAR buffer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(NewFileName, sizeof(UNICODE_STRING));

    //
    // Get the info buffer and its length
    //
    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    infoBufferLength = Data->Iopb->Parameters.SetFileInformation.Length;

    //
    // Basic validation
    //
    if (renameInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (infoBufferLength < sizeof(FILE_RENAME_INFORMATION)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Calculate maximum valid file name length based on buffer size
    // FILE_RENAME_INFORMATION has FileName[1] at the end, so:
    // MaxFileNameLength = infoBufferLength - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)
    //
    maxFileNameLength = infoBufferLength - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);

    __try {
        //
        // Read FileNameLength from potentially user-mode buffer
        //
        fileNameLength = renameInfo->FileNameLength;

        //
        // Validate FileNameLength
        //
        if (fileNameLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (fileNameLength > maxFileNameLength) {
            return STATUS_BUFFER_OVERFLOW;
        }

        //
        // Prevent excessive allocation (DoS protection)
        //
        if (fileNameLength > PSI_MAX_RENAME_BUFFER_SIZE) {
            return STATUS_NAME_TOO_LONG;
        }

        //
        // USHORT truncation protection for UNICODE_STRING
        //
        if (fileNameLength > MAXUSHORT) {
            return STATUS_NAME_TOO_LONG;
        }

        //
        // Calculate allocation size with overflow check
        //
        bufferLength = fileNameLength + sizeof(WCHAR);  // +1 for null terminator
        if (bufferLength < fileNameLength) {
            // Overflow
            return STATUS_INTEGER_OVERFLOW;
        }

        //
        // Allocate buffer (paged — callback runs at PASSIVE_LEVEL to APC_LEVEL)
        //
        buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_PAGED,
            bufferLength,
            PSI_POOL_TAG
            );

        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //
        // Copy file name from potentially user-mode buffer
        //
        RtlCopyMemory(buffer, renameInfo->FileName, fileNameLength);
        buffer[fileNameLength / sizeof(WCHAR)] = L'\0';

        //
        // Set up the output UNICODE_STRING
        //
        NewFileName->Buffer = buffer;
        NewFileName->Length = (USHORT)fileNameLength;
        NewFileName->MaximumLength = (USHORT)bufferLength;

        buffer = NULL;  // Transfer ownership to caller
        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/PreSetInfo] Exception 0x%08X accessing rename buffer\n",
                   status);
    }

    //
    // Cleanup on failure
    //
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, PSI_POOL_TAG);
    }

    return status;
}

/**
 * @brief Send telemetry event to user-mode service.
 *
 * IMPLEMENTED: Actually sends events via communication port.
 */
static VOID
PsipSendTelemetryEvent(
    _In_ HANDLE ProcessId,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _In_ PCUNICODE_STRING FileName,
    _In_ ULONG BlockReason,
    _In_ ULONG SuspicionScore,
    _In_ BOOLEAN WasBlocked
    )
{
    NTSTATUS status;
    PPSI_TELEMETRY_EVENT event = NULL;
    ULONG eventSize;
    USHORT fileNameLength;

    if (!PsipIsInitialized()) {
        return;
    }

    //
    // Calculate event size
    //
    if (FileName != NULL && FileName->Length > 0 && FileName->Buffer != NULL) {
        fileNameLength = min(FileName->Length, 1024 * sizeof(WCHAR));  // Cap at 1024 chars
    } else {
        fileNameLength = 0;
    }

    eventSize = FIELD_OFFSET(PSI_TELEMETRY_EVENT, FileName) + fileNameLength + sizeof(WCHAR);

    //
    // Allocate event structure (paged — runs at PASSIVE_LEVEL context)
    //
    event = (PPSI_TELEMETRY_EVENT)ExAllocatePool2(
        POOL_FLAG_PAGED,
        eventSize,
        PSI_POOL_TAG
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_PsiState.Stats.TelemetryEventsFailed);
        return;
    }

    RtlZeroMemory(event, eventSize);

    //
    // Populate event
    //
    event->ProcessId = ProcessId;
    event->InfoClass = InfoClass;
    event->BlockReason = BlockReason;
    event->SuspicionScore = SuspicionScore;
    event->WasBlocked = WasBlocked;
    KeQuerySystemTime(&event->Timestamp);
    event->FileNameLength = fileNameLength;

    if (fileNameLength > 0) {
        RtlCopyMemory(event->FileName, FileName->Buffer, fileNameLength);
    }
    event->FileName[fileNameLength / sizeof(WCHAR)] = L'\0';

    //
    // Send via communication port (ScanBridge).
    // Non-blocking — if the port is not connected, the event is dropped.
    //
    status = ShadowStrikeSendMessage(
        event,
        eventSize,
        NULL,
        NULL,
        NULL
        );

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_PsiState.Stats.TelemetryEventsSent);
    } else {
        InterlockedIncrement64(&g_PsiState.Stats.TelemetryEventsFailed);

        // Don't spam logs for expected failures (port not connected)
        if (status != STATUS_PORT_DISCONNECTED && status != STATUS_CONNECTION_INVALID) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/PreSetInfo] Telemetry send failed: 0x%08X\n",
                       status);
        }
    }

    ExFreePoolWithTag(event, PSI_POOL_TAG);
}

// ============================================================================
// PUBLIC STATISTICS API
// ============================================================================

/**
 * @brief Get PreSetInfo statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetPreSetInfoStats(
    _Out_opt_ PULONG64 TotalCalls,
    _Out_opt_ PULONG64 DeleteOperations,
    _Out_opt_ PULONG64 RenameOperations,
    _Out_opt_ PULONG64 BlockedOperations
    )
{
    if (g_PsiState.InitState != 2) {
        return STATUS_NOT_FOUND;
    }

    if (TotalCalls != NULL) {
        *TotalCalls = (ULONG64)g_PsiState.Stats.TotalCalls;
    }

    if (DeleteOperations != NULL) {
        *DeleteOperations = (ULONG64)g_PsiState.Stats.DeleteOperations;
    }

    if (RenameOperations != NULL) {
        *RenameOperations = (ULONG64)g_PsiState.Stats.RenameOperations;
    }

    if (BlockedOperations != NULL) {
        *BlockedOperations = (ULONG64)(
            g_PsiState.Stats.SelfProtectionBlocks +
            g_PsiState.Stats.RansomwareBlocks +
            g_PsiState.Stats.DestructionBlocks +
            g_PsiState.Stats.CredentialAccessBlocks +
            g_PsiState.Stats.SystemFileBlocks
            );
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Query process behavioral context.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeQueryPreSetInfoProcessContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN IsRansomwareSuspect,
    _Out_opt_ PBOOLEAN IsDestructionSuspect,
    _Out_opt_ PULONG SuspicionScore,
    _Out_opt_ PULONG BehaviorFlags
    )
{
    PPSI_PROCESS_CONTEXT context;

    PAGED_CODE();

    if (g_PsiState.InitState != 2) {
        return STATUS_NOT_FOUND;
    }

    context = PsipLookupProcessContext(ProcessId, FALSE);
    if (context == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (IsRansomwareSuspect != NULL) {
        *IsRansomwareSuspect = (BOOLEAN)context->IsRansomwareSuspect;
    }

    if (IsDestructionSuspect != NULL) {
        *IsDestructionSuspect = (BOOLEAN)context->IsDestructionSuspect;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = (ULONG)context->SuspicionScore;
    }

    if (BehaviorFlags != NULL) {
        *BehaviorFlags = (ULONG)context->BehaviorFlags;
    }

    PsipDereferenceProcessContext(context);

    return STATUS_SUCCESS;
}

/**
 * @brief Configure PreSetInfo behavioral thresholds.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeConfigurePreSetInfoThresholds(
    _In_ ULONG RansomwareRenameThreshold,
    _In_ ULONG RansomwareDeleteThreshold,
    _In_ ULONG DestructionDeleteThreshold
    )
{
    if (g_PsiState.InitState != 2) {
        return STATUS_NOT_FOUND;
    }

    if (RansomwareRenameThreshold > 0) {
        InterlockedExchange(&g_PsiState.RansomwareRenameThreshold, (LONG)RansomwareRenameThreshold);
    }

    if (RansomwareDeleteThreshold > 0) {
        InterlockedExchange(&g_PsiState.RansomwareDeleteThreshold, (LONG)RansomwareDeleteThreshold);
    }

    if (DestructionDeleteThreshold > 0) {
        InterlockedExchange(&g_PsiState.DestructionDeleteThreshold, (LONG)DestructionDeleteThreshold);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Configure PreSetInfo protection features.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeConfigurePreSetInfoProtection(
    _In_ BOOLEAN BlockRansomware,
    _In_ BOOLEAN BlockDestruction,
    _In_ BOOLEAN BlockCredentialAccess,
    _In_ BOOLEAN MonitorAttributes
    )
{
    if (g_PsiState.InitState != 2) {
        return STATUS_NOT_FOUND;
    }

    InterlockedExchange(&g_PsiState.BlockRansomwareBehavior, BlockRansomware);
    InterlockedExchange(&g_PsiState.BlockDataDestruction, BlockDestruction);
    InterlockedExchange(&g_PsiState.BlockCredentialAccess, BlockCredentialAccess);
    InterlockedExchange(&g_PsiState.MonitorAttributeChanges, MonitorAttributes);

    return STATUS_SUCCESS;
}

/**
 * @brief Clear behavioral tracking for a specific process.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeClearPreSetInfoProcessContext(
    _In_ HANDLE ProcessId
    )
{
    PPSI_PROCESS_CONTEXT context;

    PAGED_CODE();

    if (g_PsiState.InitState != 2) {
        return STATUS_NOT_FOUND;
    }

    context = PsipLookupProcessContext(ProcessId, FALSE);
    if (context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Reset all counters and flags
    //
    InterlockedExchange(&context->RecentRenames, 0);
    InterlockedExchange(&context->RecentDeletes, 0);
    InterlockedExchange(&context->RecentExtensionChanges, 0);
    InterlockedExchange(&context->RecentTruncations, 0);
    InterlockedExchange(&context->RecentHardLinks, 0);
    InterlockedExchange(&context->RecentAttributeChanges, 0);
    InterlockedExchange64(&context->TotalRenames, 0);
    InterlockedExchange64(&context->TotalDeletes, 0);
    InterlockedExchange64(&context->TotalExtensionChanges, 0);
    InterlockedExchange64(&context->TotalTruncations, 0);
    InterlockedExchange64(&context->TotalHardLinks, 0);
    InterlockedExchange64(&context->TotalAttributeChanges, 0);
    InterlockedExchange(&context->BehaviorFlags, 0);
    InterlockedExchange(&context->SuspicionScore, 0);
    InterlockedExchange(&context->IsRansomwareSuspect, FALSE);
    InterlockedExchange(&context->IsDestructionSuspect, FALSE);
    InterlockedExchange(&context->IsCredentialAccessSuspect, FALSE);
    InterlockedExchange(&context->IsBlocked, FALSE);

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    context->WindowStartTime = currentTime;

    PsipDereferenceProcessContext(context);

    return STATUS_SUCCESS;
}

/**
 * @brief Remove process context on process termination.
 *
 * Drops the list reference for the specified process. The context will
 * be freed once all in-flight operations release their references.
 * This prevents stale behavioral scores persisting after PID recycle.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeRemovePreSetInfoProcessContext(
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PPSI_PROCESS_CONTEXT context = NULL;

    if (g_PsiState.InitState != 2) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PsiState.ProcessContextLock);

    for (entry = g_PsiState.ProcessContextList.Flink;
         entry != &g_PsiState.ProcessContextList;
         entry = entry->Flink) {

        PPSI_PROCESS_CONTEXT candidate = CONTAINING_RECORD(entry, PSI_PROCESS_CONTEXT, ListEntry);
        if (candidate->ProcessId == ProcessId) {
            context = candidate;
            break;
        }
    }

    if (context != NULL) {
        //
        // Remove from list and drop list reference.
        // The context may still have in-flight operation references;
        // it will be freed when the last PsipDereferenceProcessContext
        // drops the refcount to zero (the re-check under lock in deref
        // will see it already removed from the list).
        //
        RemoveEntryList(&context->ListEntry);
        InitializeListHead(&context->ListEntry);
        InterlockedDecrement(&g_PsiState.ProcessContextCount);
    }

    ExReleasePushLockExclusive(&g_PsiState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (context != NULL) {
        //
        // Drop the list reference (RefCount was initialized to 2: 1 for list + 1 for caller).
        // If no in-flight operations hold a reference, this will free the context.
        //
        PsipDereferenceProcessContext(context);
    }
}
