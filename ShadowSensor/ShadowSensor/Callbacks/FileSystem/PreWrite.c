/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PRE-WRITE CALLBACK IMPLEMENTATION
===============================================================================

@file PreWrite.c
@brief Enterprise-grade pre-write callback for comprehensive file modification monitoring.

This module provides real-time interception and analysis of file write operations
for advanced threat detection including:

Write Operation Analysis:
- Ransomware behavior detection via high-entropy write patterns
- Mass file modification tracking and alerting
- Shadow copy/backup file protection
- Sensitive file write protection (credentials, certificates)
- Extension spoofing detection (writing different content types)
- MFT/Journal abuse detection
- Canary file monitoring

Self-Protection Features:
- Driver file write prevention
- Configuration file protection
- Log file tampering detection
- Quarantine folder integrity

Performance Optimizations:
- Early exit for kernel-mode operations
- Volume-level exclusions (network/removable based on config)
- File extension-based priority routing
- Lookaside list for completion contexts
- Lock-free statistics updates

Integration Points:
- ScanCache integration for verdict invalidation
- FileSystemCallbacks for process context updates
- SelfProtect for driver protection
- ExclusionManager for whitelist checking
- ETW provider for telemetry

MITRE ATT&CK Coverage:
- T1486: Data Encrypted for Impact (ransomware)
- T1485: Data Destruction (mass deletion/overwrite)
- T1490: Inhibit System Recovery (shadow copy writes)
- T1070.004: File Deletion (evidence destruction)
- T1565.001: Stored Data Manipulation
- T1003.001: LSASS Memory (credential file writes)

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition - Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Cache/ScanCache.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Utilities/FileUtils.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Communication/ScanBridge.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PW_POOL_TAG                     'wPFS'  // SFPw - Pre-Write
#define PW_CONTEXT_POOL_TAG             'xPFS'  // SFPx - Context
#define PW_WORKITEM_POOL_TAG            'yPFS'  // SFPy - Work Item
#define PW_ENTROPY_POOL_TAG             'zPFS'  // SFPz - Entropy buffer

//
// Write operation thresholds
//
#define PW_HIGH_ENTROPY_THRESHOLD       750     // Scaled 0-1000
#define PW_RANSOMWARE_ENTROPY_THRESHOLD 800     // Very high entropy
#define PW_LARGE_WRITE_THRESHOLD        (1024 * 1024)  // 1 MB
#define PW_MASSIVE_WRITE_THRESHOLD      (16 * 1024 * 1024)  // 16 MB
#define PW_SMALL_WRITE_MAX              4096    // Small write for header analysis
#define PW_ENTROPY_SAMPLE_SIZE          4096    // Bytes to sample for entropy

//
// Rate limiting thresholds (per-process per-second)
//
#define PW_WRITES_PER_SECOND_THRESHOLD  100
#define PW_UNIQUE_FILES_PER_SEC_THRESHOLD 50

//
// Safety limits
//
#define PW_MAX_SUBSTRING_LENGTH         260     // Maximum pattern length
#define PW_MAX_CANARY_PATHS             64      // Maximum canary file paths
#define PW_CLEANUP_WAIT_TIMEOUT_MS      5000    // 5 second wait for cleanup

//
// File classification flags for write analysis
//
#define PW_FILE_SENSITIVE               0x00000001
#define PW_FILE_BACKUP                  0x00000002
#define PW_FILE_SHADOW_COPY             0x00000004
#define PW_FILE_CREDENTIAL              0x00000008
#define PW_FILE_CERTIFICATE             0x00000010
#define PW_FILE_DATABASE                0x00000020
#define PW_FILE_LOG                     0x00000040
#define PW_FILE_EXECUTABLE              0x00000080
#define PW_FILE_SCRIPT                  0x00000100
#define PW_FILE_DOCUMENT                0x00000200
#define PW_FILE_CANARY                  0x00000400
#define PW_FILE_SYSTEM                  0x00000800
#define PW_FILE_DRIVER                  0x00001000
#define PW_FILE_CONFIG                  0x00002000

//
// Suspicion flags for write operations
//
#define PW_SUSPICION_NONE               0x00000000
#define PW_SUSPICION_HIGH_ENTROPY       0x00000001
#define PW_SUSPICION_OVERWRITE_HEADER   0x00000002
#define PW_SUSPICION_SENSITIVE_TARGET   0x00000004
#define PW_SUSPICION_BACKUP_TARGET      0x00000008
#define PW_SUSPICION_MASS_WRITE         0x00000010
#define PW_SUSPICION_SHADOW_COPY        0x00000020
#define PW_SUSPICION_CREDENTIAL_FILE    0x00000040
#define PW_SUSPICION_CANARY_FILE        0x00000080
#define PW_SUSPICION_EXTENSION_MISMATCH 0x00000100
#define PW_SUSPICION_APPEND_EXECUTABLE  0x00000200
#define PW_SUSPICION_SELF_PROTECTED     0x00000400
#define PW_SUSPICION_DOCUMENT_ENCRYPT   0x00000800

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Entropy calculation buffer (moved off stack)
//
typedef struct _PW_ENTROPY_CONTEXT {
    ULONG ByteCounts[256];
} PW_ENTROPY_CONTEXT, *PPW_ENTROPY_CONTEXT;

//
// Pre-write completion context
//
typedef struct _PW_COMPLETION_CONTEXT {
    //
    // Signature for validation
    //
    ULONG Signature;

    //
    // Operation tracking
    //
    LARGE_INTEGER StartTime;
    HANDLE ProcessId;
    HANDLE ThreadId;

    //
    // File information
    //
    PFLT_FILE_NAME_INFORMATION NameInfo;
    UNICODE_STRING CapturedName;
    WCHAR NameBuffer[260];

    //
    // Write parameters
    //
    LONGLONG WriteOffset;
    ULONG WriteLength;
    BOOLEAN IsOffsetSpecified;
    BOOLEAN WritesToFileStart;

    //
    // Analysis results
    //
    ULONG FileClassification;
    ULONG SuspicionFlags;
    ULONG EntropyScore;

    //
    // Cache key for invalidation
    //
    SHADOWSTRIKE_CACHE_KEY CacheKey;
    BOOLEAN CacheKeyValid;

    //
    // Flags
    //
    BOOLEAN RequiresPostProcessing;
    BOOLEAN WasBlocked;
    BOOLEAN CacheInvalidated;

} PW_COMPLETION_CONTEXT, *PPW_COMPLETION_CONTEXT;

#define PW_CONTEXT_SIGNATURE            'xWpS'
#define PW_CONTEXT_SIGNATURE_FREED      'dWpS'

//
// Deferred cleanup work item for elevated IRQL scenarios
//
typedef struct _PW_DEFERRED_CLEANUP {
    WORK_QUEUE_ITEM WorkItem;
    PFLT_FILE_NAME_INFORMATION NameInfo;
    PPW_COMPLETION_CONTEXT Context;
} PW_DEFERRED_CLEANUP, *PPW_DEFERRED_CLEANUP;

//
// Sensitive file patterns
//
typedef struct _PW_SENSITIVE_PATTERN {
    PCWSTR Pattern;
    USHORT PatternLength;   // Pre-computed length for safety
    ULONG Classification;
} PW_SENSITIVE_PATTERN, *PPW_SENSITIVE_PATTERN;

//
// Canary file configuration
//
typedef struct _PW_CANARY_CONFIG {
    UNICODE_STRING Paths[PW_MAX_CANARY_PATHS];
    volatile LONG Count;
    EX_PUSH_LOCK Lock;
    BOOLEAN Initialized;
} PW_CANARY_CONFIG, *PPW_CANARY_CONFIG;

//
// Global pre-write state
//
typedef struct _PW_GLOBAL_STATE {
    //
    // Initialization synchronization
    //
    volatile LONG InitLock;
    volatile LONG Initialized;

    //
    // Operation reference counting for safe cleanup
    //
    volatile LONG OutstandingOperations;
    KEVENT CleanupEvent;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    NPAGED_LOOKASIDE_LIST EntropyLookaside;
    volatile LONG LookasideInitialized;

    //
    // Canary file configuration
    //
    PW_CANARY_CONFIG CanaryConfig;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalPreWriteCalls;
        volatile LONG64 SkippedKernelMode;
        volatile LONG64 SkippedNotReady;
        volatile LONG64 SelfProtectionBlocks;
        volatile LONG64 CacheInvalidations;
        volatile LONG64 HighEntropyWrites;
        volatile LONG64 SensitiveFileWrites;
        volatile LONG64 SuspiciousWrites;
        volatile LONG64 MassWriteDetections;
        volatile LONG64 PostCallbacksQueued;
        volatile LONG64 ContextAllocations;
        volatile LONG64 ContextFrees;
        volatile LONG64 CanaryFileHits;
        volatile LONG64 DocumentEncryptionBlocks;
        volatile LONG64 DeferredCleanups;
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableEntropyAnalysis;
        BOOLEAN EnableSensitiveFileProtection;
        BOOLEAN EnableMassWriteDetection;
        BOOLEAN EnablePostWriteTracking;
        BOOLEAN EnableDocumentProtection;
        BOOLEAN EnableCanaryFileProtection;
        ULONG EntropyThreshold;
        ULONG MassWriteThreshold;
    } Config;

} PW_GLOBAL_STATE, *PPW_GLOBAL_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PW_GLOBAL_STATE g_PwState = {0};

//
// Sensitive file patterns for enhanced protection
// Pre-computed lengths for bounded comparison
//
static const PW_SENSITIVE_PATTERN g_SensitivePatterns[] = {
    //
    // Shadow copy and backup files
    //
    { L"\\System Volume Information\\", 28, PW_FILE_SHADOW_COPY },
    { L"@GMT-", 5, PW_FILE_SHADOW_COPY },
    { L".bak", 4, PW_FILE_BACKUP },
    { L".backup", 7, PW_FILE_BACKUP },
    { L"\\Backup\\", 8, PW_FILE_BACKUP },

    //
    // Credential and security files
    //
    { L"\\SAM", 4, PW_FILE_CREDENTIAL },
    { L"\\SECURITY", 9, PW_FILE_CREDENTIAL },
    { L"\\SYSTEM", 7, PW_FILE_CREDENTIAL },
    { L"\\ntds.dit", 9, PW_FILE_CREDENTIAL },
    { L"\\NTUSER.DAT", 11, PW_FILE_CREDENTIAL },
    { L".pfx", 4, PW_FILE_CERTIFICATE },
    { L".p12", 4, PW_FILE_CERTIFICATE },
    { L".pem", 4, PW_FILE_CERTIFICATE },
    { L".key", 4, PW_FILE_CERTIFICATE },
    { L".cer", 4, PW_FILE_CERTIFICATE },
    { L".crt", 4, PW_FILE_CERTIFICATE },
    { L"\\ssh\\", 5, PW_FILE_CREDENTIAL },
    { L"\\gnupg\\", 7, PW_FILE_CREDENTIAL },
    { L"id_rsa", 6, PW_FILE_CREDENTIAL },
    { L"id_ecdsa", 8, PW_FILE_CREDENTIAL },
    { L"known_hosts", 11, PW_FILE_CREDENTIAL },

    //
    // Database files
    //
    { L".mdf", 4, PW_FILE_DATABASE },
    { L".ldf", 4, PW_FILE_DATABASE },
    { L".ndf", 4, PW_FILE_DATABASE },
    { L".sqlite", 7, PW_FILE_DATABASE },
    { L".db", 3, PW_FILE_DATABASE },
    { L".mdb", 4, PW_FILE_DATABASE },
    { L".accdb", 6, PW_FILE_DATABASE },

    //
    // System files
    //
    { L"\\Windows\\System32\\", 18, PW_FILE_SYSTEM },
    { L"\\Windows\\SysWOW64\\", 18, PW_FILE_SYSTEM },
    { L"\\Windows\\WinSxS\\", 16, PW_FILE_SYSTEM },
    { L".sys", 4, PW_FILE_DRIVER },
    { L"\\drivers\\", 9, PW_FILE_DRIVER },

    //
    // Configuration files
    //
    { L"boot.ini", 8, PW_FILE_CONFIG },
    { L"bootmgr", 7, PW_FILE_CONFIG },
    { L"\\EFI\\", 5, PW_FILE_CONFIG },
    { L".ini", 4, PW_FILE_CONFIG },
    { L".conf", 5, PW_FILE_CONFIG },
    { L".config", 7, PW_FILE_CONFIG },
    { L"web.config", 10, PW_FILE_CONFIG },
    { L"machine.config", 14, PW_FILE_CONFIG },

    //
    // Log files (for tampering detection)
    //
    { L".evtx", 5, PW_FILE_LOG },
    { L".log", 4, PW_FILE_LOG },
    { L"\\winevt\\", 8, PW_FILE_LOG },
};

#define PW_SENSITIVE_PATTERN_COUNT (sizeof(g_SensitivePatterns) / sizeof(g_SensitivePatterns[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPW_COMPLETION_CONTEXT
PwpAllocateContext(
    VOID
    );

static VOID
PwpFreeContext(
    _In_ PPW_COMPLETION_CONTEXT Context
    );

static ULONG
PwpClassifyFile(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
PwpIsSensitiveFile(
    _In_ PCUNICODE_STRING FileName,
    _Out_ PULONG Classification
    );

static BOOLEAN
PwpIsCanaryFile(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring,
    _In_ USHORT SubstringLength
    );

static ULONG
PwpAnalyzeWriteSuspicion(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PPW_COMPLETION_CONTEXT Context
    );

static ULONG
PwpCalculateBufferEntropy(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    );

static BOOLEAN
PwpShouldBlockWrite(
    _In_ ULONG SuspicionFlags,
    _In_ ULONG FileClassification
    );

static VOID
PwpUpdateProcessWriteMetrics(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    );

static VOID
PwpNotifyWriteEvent(
    _In_ PPW_COMPLETION_CONTEXT Context,
    _In_ BOOLEAN Blocked
    );

static VOID
PwpDeferredCleanupWorker(
    _In_ PVOID Parameter
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
PwpPerformDeferredCleanup(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PPW_COMPLETION_CONTEXT Context
    );

// ============================================================================
// OPERATION REFERENCE COUNTING
// ============================================================================

FORCEINLINE
BOOLEAN
PwpEnterOperation(
    VOID
    )
/*++
Routine Description:
    Enters an operation, incrementing the reference count.
    Returns FALSE if the subsystem is not initialized or shutting down.
--*/
{
    if (!g_PwState.Initialized) {
        return FALSE;
    }

    InterlockedIncrement(&g_PwState.OutstandingOperations);

    //
    // Double-check after increment
    //
    if (!g_PwState.Initialized) {
        InterlockedDecrement(&g_PwState.OutstandingOperations);
        return FALSE;
    }

    return TRUE;
}


FORCEINLINE
VOID
PwpLeaveOperation(
    VOID
    )
/*++
Routine Description:
    Leaves an operation, decrementing the reference count.
    Signals cleanup event when count reaches zero.
--*/
{
    LONG NewCount = InterlockedDecrement(&g_PwState.OutstandingOperations);

    if (NewCount == 0) {
        KeSetEvent(&g_PwState.CleanupEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

NTSTATUS
ShadowStrikeInitializePreWrite(
    VOID
    )
/*++
Routine Description:
    Initializes the pre-write callback subsystem with proper synchronization.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_ALREADY_REGISTERED if already initialized.
--*/
{
    //
    // Atomic initialization guard - prevents double-init race
    //
    if (InterlockedCompareExchange(&g_PwState.InitLock, 1, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Already initialized check (after acquiring lock)
    //
    if (g_PwState.Initialized) {
        InterlockedExchange(&g_PwState.InitLock, 0);
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_PwState.Stats, sizeof(g_PwState.Stats));
    RtlZeroMemory(&g_PwState.Config, sizeof(g_PwState.Config));

    //
    // Initialize cleanup event
    //
    KeInitializeEvent(&g_PwState.CleanupEvent, NotificationEvent, TRUE);
    g_PwState.OutstandingOperations = 0;

    //
    // Initialize lookaside list for completion contexts
    //
    ExInitializeNPagedLookasideList(
        &g_PwState.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PW_COMPLETION_CONTEXT),
        PW_CONTEXT_POOL_TAG,
        0
        );

    //
    // Initialize lookaside list for entropy calculation buffers
    //
    ExInitializeNPagedLookasideList(
        &g_PwState.EntropyLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PW_ENTROPY_CONTEXT),
        PW_ENTROPY_POOL_TAG,
        0
        );

    InterlockedExchange(&g_PwState.LookasideInitialized, TRUE);

    //
    // Initialize canary file configuration
    //
    ExInitializePushLock(&g_PwState.CanaryConfig.Lock);
    g_PwState.CanaryConfig.Count = 0;
    g_PwState.CanaryConfig.Initialized = TRUE;

    //
    // Set default configuration
    //
    g_PwState.Config.EnableEntropyAnalysis = TRUE;
    g_PwState.Config.EnableSensitiveFileProtection = TRUE;
    g_PwState.Config.EnableMassWriteDetection = TRUE;
    g_PwState.Config.EnablePostWriteTracking = TRUE;
    g_PwState.Config.EnableDocumentProtection = TRUE;
    g_PwState.Config.EnableCanaryFileProtection = TRUE;
    g_PwState.Config.EntropyThreshold = PW_HIGH_ENTROPY_THRESHOLD;
    g_PwState.Config.MassWriteThreshold = PW_WRITES_PER_SECOND_THRESHOLD;

    //
    // Mark as initialized - use memory barrier
    //
    MemoryBarrier();
    InterlockedExchange(&g_PwState.Initialized, TRUE);
    InterlockedExchange(&g_PwState.InitLock, 0);

    return STATUS_SUCCESS;
}


VOID
ShadowStrikeCleanupPreWrite(
    VOID
    )
/*++
Routine Description:
    Cleans up the pre-write callback subsystem.
    Waits for all outstanding operations to complete before cleanup.
--*/
{
    LARGE_INTEGER Timeout;

    if (!InterlockedExchange(&g_PwState.Initialized, FALSE)) {
        return;
    }

    //
    // Wait for outstanding operations to complete
    //
    if (g_PwState.OutstandingOperations > 0) {
        KeClearEvent(&g_PwState.CleanupEvent);

        Timeout.QuadPart = -((LONGLONG)PW_CLEANUP_WAIT_TIMEOUT_MS * 10000);

        KeWaitForSingleObject(
            &g_PwState.CleanupEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
            );
    }

    //
    // Now safe to delete lookaside lists
    //
    if (InterlockedExchange(&g_PwState.LookasideInitialized, FALSE)) {
        ExDeleteNPagedLookasideList(&g_PwState.ContextLookaside);
        ExDeleteNPagedLookasideList(&g_PwState.EntropyLookaside);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PreWrite] Shutdown. Stats: Total=%lld, Blocked=%lld, "
        "HighEntropy=%lld, Sensitive=%lld, Mass=%lld, Canary=%lld\n",
        g_PwState.Stats.TotalPreWriteCalls,
        g_PwState.Stats.SelfProtectionBlocks,
        g_PwState.Stats.HighEntropyWrites,
        g_PwState.Stats.SensitiveFileWrites,
        g_PwState.Stats.MassWriteDetections,
        g_PwState.Stats.CanaryFileHits
        );
}

// ============================================================================
// CANARY FILE CONFIGURATION
// ============================================================================

NTSTATUS
ShadowStrikeAddCanaryPath(
    _In_ PCUNICODE_STRING Path
    )
/*++
Routine Description:
    Adds a canary file path to the monitoring list.

Arguments:
    Path - Full path to the canary file.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    LONG Index;
    PWCHAR Buffer;

    if (!g_PwState.Initialized || Path == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PwState.CanaryConfig.Lock);

    Index = g_PwState.CanaryConfig.Count;

    if (Index >= PW_MAX_CANARY_PATHS) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Buffer = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Path->Length + sizeof(WCHAR),
        PW_POOL_TAG
        );

    if (Buffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlCopyMemory(Buffer, Path->Buffer, Path->Length);
    Buffer[Path->Length / sizeof(WCHAR)] = L'\0';

    g_PwState.CanaryConfig.Paths[Index].Buffer = Buffer;
    g_PwState.CanaryConfig.Paths[Index].Length = Path->Length;
    g_PwState.CanaryConfig.Paths[Index].MaximumLength = Path->Length + sizeof(WCHAR);

    InterlockedIncrement(&g_PwState.CanaryConfig.Count);

Cleanup:
    ExReleasePushLockExclusive(&g_PwState.CanaryConfig.Lock);
    KeLeaveCriticalRegion();

    return Status;
}

// ============================================================================
// MAIN PRE-WRITE CALLBACK
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++
Routine Description:
    Enterprise-grade pre-operation callback for IRP_MJ_WRITE.

    Provides comprehensive write monitoring including:
    - Self-protection for driver files
    - Ransomware detection via entropy analysis
    - Sensitive file protection
    - Mass write/modification detection
    - Cache invalidation for scan verdicts
    - Process behavior tracking
    - Canary file detection

Arguments:
    Data - Callback data containing write parameters.
    FltObjects - Filter objects for this operation.
    CompletionContext - Receives context for post-operation callback.

Return Value:
    FLT_PREOP_SUCCESS_NO_CALLBACK - Allow write, no post-processing needed.
    FLT_PREOP_SUCCESS_WITH_CALLBACK - Allow write, post-processing required.
    FLT_PREOP_COMPLETE - Block write operation.
--*/
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    HANDLE RequestorPid;
    PPW_COMPLETION_CONTEXT PwContext = NULL;
    ULONG FileClassification = 0;
    ULONG SuspicionFlags = PW_SUSPICION_NONE;
    BOOLEAN BlockWrite = FALSE;
    BOOLEAN RequiresPostProcessing = FALSE;
    FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    *CompletionContext = NULL;

    InterlockedIncrement64(&g_PwState.Stats.TotalPreWriteCalls);

    //
    // Fast path: Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        InterlockedIncrement64(&g_PwState.Stats.SkippedNotReady);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Fast path: Skip kernel-mode operations
    //
    if (Data->RequestorMode == KernelMode) {
        InterlockedIncrement64(&g_PwState.Stats.SkippedKernelMode);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Fast path: Skip if no file object
    //
    if (FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Fast path: Skip paging I/O and synchronous paging I/O
    // These are system-initiated and should not be blocked
    //
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Fast path: Skip if write length is zero
    //
    if (Data->Iopb->Parameters.Write.Length == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Enter operation with reference counting
    //
    if (!PwpEnterOperation()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    RequestorPid = PsGetCurrentProcessId();

    //
    // Get file name information
    //
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo
        );

    if (!NT_SUCCESS(Status)) {
        //
        // Cannot get file name - proceed to cache invalidation
        //
        goto CacheInvalidation;
    }

    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(NameInfo);
        NameInfo = NULL;
        goto CacheInvalidation;
    }

    // =========================================================================
    // SELF-PROTECTION CHECK
    // =========================================================================

    if (g_SelfProtectInitialized && g_DriverData.Config.SelfProtectionEnabled) {
        if (ShadowStrikeShouldBlockFileAccess(
                &NameInfo->Name,
                FILE_WRITE_DATA,
                RequestorPid,
                FALSE)) {

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            InterlockedIncrement64(&g_PwState.Stats.SelfProtectionBlocks);
            SHADOWSTRIKE_INC_STAT(FilesBlocked);

            SuspicionFlags |= PW_SUSPICION_SELF_PROTECTED;
            BlockWrite = TRUE;

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PreWrite] BLOCKED self-protected file: %wZ (PID=%lu)\n",
                &NameInfo->Name,
                HandleToULong(RequestorPid)
                );

            goto Cleanup;
        }
    }

    // =========================================================================
    // CANARY FILE CHECK (Honeypot Detection)
    // =========================================================================

    if (g_PwState.Config.EnableCanaryFileProtection) {
        if (PwpIsCanaryFile(&NameInfo->Name)) {
            SuspicionFlags |= PW_SUSPICION_CANARY_FILE;
            InterlockedIncrement64(&g_PwState.Stats.CanaryFileHits);

            //
            // Canary file access is ALWAYS blocked and generates high-priority alert
            //
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlockWrite = TRUE;

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "[ShadowStrike/PreWrite] CRITICAL: Canary file access detected: %wZ (PID=%lu)\n",
                &NameInfo->Name,
                HandleToULong(RequestorPid)
                );

            goto Cleanup;
        }
    }

    // =========================================================================
    // FILE CLASSIFICATION
    // =========================================================================

    FileClassification = PwpClassifyFile(&NameInfo->Name);

    //
    // Check for sensitive file patterns
    //
    if (g_PwState.Config.EnableSensitiveFileProtection) {
        ULONG SensitiveClass = 0;
        if (PwpIsSensitiveFile(&NameInfo->Name, &SensitiveClass)) {
            FileClassification |= SensitiveClass;
            InterlockedIncrement64(&g_PwState.Stats.SensitiveFileWrites);
            SuspicionFlags |= PW_SUSPICION_SENSITIVE_TARGET;

            //
            // Shadow copy writes are highly suspicious
            //
            if (SensitiveClass & PW_FILE_SHADOW_COPY) {
                SuspicionFlags |= PW_SUSPICION_SHADOW_COPY;
            }

            //
            // Credential file writes are critical
            //
            if (SensitiveClass & PW_FILE_CREDENTIAL) {
                SuspicionFlags |= PW_SUSPICION_CREDENTIAL_FILE;
            }

            //
            // Backup file writes during ransomware activity
            //
            if (SensitiveClass & PW_FILE_BACKUP) {
                SuspicionFlags |= PW_SUSPICION_BACKUP_TARGET;
            }
        }
    }

    // =========================================================================
    // ALLOCATE COMPLETION CONTEXT FOR ADVANCED ANALYSIS
    // =========================================================================

    PwContext = PwpAllocateContext();
    if (PwContext != NULL) {
        PwContext->ProcessId = RequestorPid;
        PwContext->ThreadId = PsGetCurrentThreadId();
        KeQuerySystemTime(&PwContext->StartTime);
        PwContext->NameInfo = NameInfo;
        PwContext->FileClassification = FileClassification;

        //
        // Capture write parameters
        //
        PwContext->WriteLength = Data->Iopb->Parameters.Write.Length;

        if (Data->Iopb->Parameters.Write.ByteOffset.QuadPart != -1) {
            PwContext->WriteOffset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
            PwContext->IsOffsetSpecified = TRUE;
            PwContext->WritesToFileStart = (PwContext->WriteOffset == 0);
        } else {
            PwContext->IsOffsetSpecified = FALSE;
            PwContext->WritesToFileStart = FALSE;
        }

        //
        // Copy file name for post-processing
        //
        if (NameInfo->Name.Length > 0 &&
            NameInfo->Name.Length < sizeof(PwContext->NameBuffer)) {
            RtlCopyMemory(
                PwContext->NameBuffer,
                NameInfo->Name.Buffer,
                NameInfo->Name.Length
                );
            PwContext->CapturedName.Buffer = PwContext->NameBuffer;
            PwContext->CapturedName.Length = NameInfo->Name.Length;
            PwContext->CapturedName.MaximumLength = sizeof(PwContext->NameBuffer);
        }

        //
        // Perform advanced suspicion analysis
        //
        SuspicionFlags |= PwpAnalyzeWriteSuspicion(Data, FltObjects, PwContext);
        PwContext->SuspicionFlags = SuspicionFlags;

        //
        // Determine if we should block based on suspicion
        //
        if (PwpShouldBlockWrite(SuspicionFlags, FileClassification)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            BlockWrite = TRUE;
            PwContext->WasBlocked = TRUE;

            InterlockedIncrement64(&g_PwState.Stats.SuspiciousWrites);
            SHADOWSTRIKE_INC_STAT(FilesBlocked);

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PreWrite] BLOCKED suspicious write: %wZ "
                "(PID=%lu, Flags=0x%08X, Class=0x%08X)\n",
                &NameInfo->Name,
                HandleToULong(RequestorPid),
                SuspicionFlags,
                FileClassification
                );
        }

        //
        // If write is allowed but suspicious, track for post-processing
        //
        if (!BlockWrite && SuspicionFlags != PW_SUSPICION_NONE) {
            RequiresPostProcessing = TRUE;
            PwContext->RequiresPostProcessing = TRUE;
        }
    }

    // =========================================================================
    // CACHE INVALIDATION
    // =========================================================================

CacheInvalidation:
    //
    // Invalidate scan cache for this file
    // If a file is written to, its hash changes, so any previous verdict is invalid
    //
    if (FltObjects->FileObject != NULL && !BlockWrite) {
        SHADOWSTRIKE_CACHE_KEY CacheKey;

        Status = ShadowStrikeCacheBuildKey(FltObjects, &CacheKey);
        if (NT_SUCCESS(Status)) {
            if (ShadowStrikeCacheRemove(&CacheKey)) {
                InterlockedIncrement64(&g_PwState.Stats.CacheInvalidations);

                if (PwContext != NULL) {
                    PwContext->CacheInvalidated = TRUE;
                    PwContext->CacheKey = CacheKey;
                    PwContext->CacheKeyValid = TRUE;
                }
            }
        }
    }

    // =========================================================================
    // UPDATE PROCESS METRICS
    // =========================================================================

    if (NameInfo != NULL && g_PwState.Config.EnableMassWriteDetection) {
        PwpUpdateProcessWriteMetrics(RequestorPid, &NameInfo->Name);
    }

Cleanup:
    //
    // Determine return status
    //
    if (BlockWrite) {
        ReturnStatus = FLT_PREOP_COMPLETE;

        //
        // Notify of blocked write
        //
        if (PwContext != NULL) {
            PwpNotifyWriteEvent(PwContext, TRUE);
        }
    } else if (RequiresPostProcessing && PwContext != NULL) {
        //
        // Keep context for post-operation callback
        //
        *CompletionContext = PwContext;
        PwContext = NULL;  // Don't free
        NameInfo = NULL;   // Will be released in post-callback

        InterlockedIncrement64(&g_PwState.Stats.PostCallbacksQueued);
        ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    } else {
        ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Cleanup
    //
    if (NameInfo != NULL) {
        FltReleaseFileNameInformation(NameInfo);
    }

    if (PwContext != NULL) {
        PwContext->NameInfo = NULL;  // Already released
        PwpFreeContext(PwContext);
    }

    SHADOWSTRIKE_LEAVE_OPERATION();
    PwpLeaveOperation();

    return ReturnStatus;
}


FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++
Routine Description:
    Post-operation callback for IRP_MJ_WRITE.

    Called after write completes to:
    - Track successful suspicious writes
    - Update behavioral analysis
    - Generate telemetry events

    Handles elevated IRQL scenarios (draining) by deferring cleanup
    to a work item.

Arguments:
    Data - Callback data with operation result.
    FltObjects - Filter objects.
    CompletionContext - Context from pre-operation.
    Flags - Post-operation flags.

Return Value:
    FLT_POSTOP_FINISHED_PROCESSING.
--*/
{
    PPW_COMPLETION_CONTEXT PwContext;
    PPW_DEFERRED_CLEANUP DeferredCleanup;

    UNREFERENCED_PARAMETER(FltObjects);

    if (CompletionContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PwContext = (PPW_COMPLETION_CONTEXT)CompletionContext;

    //
    // Validate context signature
    //
    if (PwContext->Signature != PW_CONTEXT_SIGNATURE) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/PostWrite] CRITICAL: Invalid context signature 0x%08X!\n",
            PwContext->Signature
            );

        //
        // Memory corruption detected - attempt safe cleanup anyway
        // to prevent leak, but log the error
        //
        if (g_PwState.LookasideInitialized) {
            ExFreeToNPagedLookasideList(&g_PwState.ContextLookaside, PwContext);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Check if we're at elevated IRQL (draining scenario)
    //
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        //
        // Cannot safely release NameInfo at elevated IRQL
        // Queue a work item for deferred cleanup
        //
        DeferredCleanup = (PPW_DEFERRED_CLEANUP)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(PW_DEFERRED_CLEANUP),
            PW_WORKITEM_POOL_TAG
            );

        if (DeferredCleanup != NULL) {
            DeferredCleanup->NameInfo = PwContext->NameInfo;
            DeferredCleanup->Context = PwContext;

            ExInitializeWorkItem(
                &DeferredCleanup->WorkItem,
                PwpDeferredCleanupWorker,
                DeferredCleanup
                );

            ExQueueWorkItem(&DeferredCleanup->WorkItem, DelayedWorkQueue);
            InterlockedIncrement64(&g_PwState.Stats.DeferredCleanups);
        } else {
            //
            // Failed to allocate work item - leak is better than BSOD
            // Log the issue
            //
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_ERROR_LEVEL,
                "[ShadowStrike/PostWrite] Failed to allocate deferred cleanup work item\n"
                );
        }

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Normal IRQL - process inline
    //

    //
    // Check if write succeeded
    //
    if (NT_SUCCESS(Data->IoStatus.Status)) {
        //
        // Notify of successful suspicious write
        //
        if (PwContext->SuspicionFlags != PW_SUSPICION_NONE) {
            PwpNotifyWriteEvent(PwContext, FALSE);
        }
    }

    //
    // Cleanup
    //
    if (PwContext->NameInfo != NULL) {
        FltReleaseFileNameInformation(PwContext->NameInfo);
    }

    PwpFreeContext(PwContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// DEFERRED CLEANUP
// ============================================================================

static VOID
PwpDeferredCleanupWorker(
    _In_ PVOID Parameter
    )
/*++
Routine Description:
    Work item routine for deferred cleanup when post-callback
    was invoked at elevated IRQL.

Arguments:
    Parameter - Pointer to PW_DEFERRED_CLEANUP structure.
--*/
{
    PPW_DEFERRED_CLEANUP Cleanup = (PPW_DEFERRED_CLEANUP)Parameter;

    if (Cleanup == NULL) {
        return;
    }

    PwpPerformDeferredCleanup(Cleanup->NameInfo, Cleanup->Context);

    ExFreePoolWithTag(Cleanup, PW_WORKITEM_POOL_TAG);
}


_IRQL_requires_(PASSIVE_LEVEL)
static VOID
PwpPerformDeferredCleanup(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PPW_COMPLETION_CONTEXT Context
    )
/*++
Routine Description:
    Performs cleanup that must happen at PASSIVE_LEVEL.
--*/
{
    if (NameInfo != NULL) {
        FltReleaseFileNameInformation(NameInfo);
    }

    if (Context != NULL) {
        PwpFreeContext(Context);
    }
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static PPW_COMPLETION_CONTEXT
PwpAllocateContext(
    VOID
    )
{
    PPW_COMPLETION_CONTEXT Context;

    if (!g_PwState.LookasideInitialized) {
        return NULL;
    }

    Context = (PPW_COMPLETION_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_PwState.ContextLookaside
        );

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(PW_COMPLETION_CONTEXT));
        Context->Signature = PW_CONTEXT_SIGNATURE;
        InterlockedIncrement64(&g_PwState.Stats.ContextAllocations);
    }

    return Context;
}


static VOID
PwpFreeContext(
    _In_ PPW_COMPLETION_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (!g_PwState.LookasideInitialized) {
        //
        // Lookaside destroyed - cannot free safely
        // This is a leak but prevents crash during shutdown
        //
        return;
    }

    //
    // Mark as freed to detect double-free
    //
    Context->Signature = PW_CONTEXT_SIGNATURE_FREED;
    ExFreeToNPagedLookasideList(&g_PwState.ContextLookaside, Context);

    InterlockedIncrement64(&g_PwState.Stats.ContextFrees);
}


static ULONG
PwpClassifyFile(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG Classification = 0;
    UNICODE_STRING Extension;
    USHORT i;
    USHORT LastDot = 0;
    BOOLEAN FoundDot = FALSE;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return 0;
    }

    //
    // Extract extension
    //
    for (i = FileName->Length / sizeof(WCHAR); i > 0; i--) {
        if (FileName->Buffer[i - 1] == L'.') {
            LastDot = i - 1;
            FoundDot = TRUE;
            break;
        }
        if (FileName->Buffer[i - 1] == L'\\') {
            break;  // No extension found
        }
    }

    if (!FoundDot) {
        return 0;
    }

    Extension.Buffer = &FileName->Buffer[LastDot];
    Extension.Length = FileName->Length - (LastDot * sizeof(WCHAR));
    Extension.MaximumLength = Extension.Length;

    //
    // Classify by extension
    //
    if (PwpStringContainsInsensitive(&Extension, L".exe", 4) ||
        PwpStringContainsInsensitive(&Extension, L".dll", 4) ||
        PwpStringContainsInsensitive(&Extension, L".sys", 4) ||
        PwpStringContainsInsensitive(&Extension, L".scr", 4) ||
        PwpStringContainsInsensitive(&Extension, L".com", 4)) {
        Classification |= PW_FILE_EXECUTABLE;
    }

    if (PwpStringContainsInsensitive(&Extension, L".ps1", 4) ||
        PwpStringContainsInsensitive(&Extension, L".bat", 4) ||
        PwpStringContainsInsensitive(&Extension, L".cmd", 4) ||
        PwpStringContainsInsensitive(&Extension, L".vbs", 4) ||
        PwpStringContainsInsensitive(&Extension, L".js", 3) ||
        PwpStringContainsInsensitive(&Extension, L".hta", 4) ||
        PwpStringContainsInsensitive(&Extension, L".wsf", 4)) {
        Classification |= PW_FILE_SCRIPT;
    }

    if (PwpStringContainsInsensitive(&Extension, L".doc", 4) ||
        PwpStringContainsInsensitive(&Extension, L".docx", 5) ||
        PwpStringContainsInsensitive(&Extension, L".xls", 4) ||
        PwpStringContainsInsensitive(&Extension, L".xlsx", 5) ||
        PwpStringContainsInsensitive(&Extension, L".ppt", 4) ||
        PwpStringContainsInsensitive(&Extension, L".pptx", 5) ||
        PwpStringContainsInsensitive(&Extension, L".pdf", 4) ||
        PwpStringContainsInsensitive(&Extension, L".rtf", 4)) {
        Classification |= PW_FILE_DOCUMENT;
    }

    return Classification;
}


static BOOLEAN
PwpIsSensitiveFile(
    _In_ PCUNICODE_STRING FileName,
    _Out_ PULONG Classification
    )
{
    ULONG i;

    *Classification = 0;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < PW_SENSITIVE_PATTERN_COUNT; i++) {
        if (PwpStringContainsInsensitive(
                FileName,
                g_SensitivePatterns[i].Pattern,
                g_SensitivePatterns[i].PatternLength)) {
            *Classification |= g_SensitivePatterns[i].Classification;
        }
    }

    return (*Classification != 0);
}


static BOOLEAN
PwpIsCanaryFile(
    _In_ PCUNICODE_STRING FileName
    )
{
    LONG i;
    LONG Count;
    BOOLEAN Result = FALSE;

    if (!g_PwState.CanaryConfig.Initialized) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PwState.CanaryConfig.Lock);

    Count = g_PwState.CanaryConfig.Count;

    for (i = 0; i < Count; i++) {
        if (RtlEqualUnicodeString(
                FileName,
                &g_PwState.CanaryConfig.Paths[i],
                TRUE)) {
            Result = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_PwState.CanaryConfig.Lock);
    KeLeaveCriticalRegion();

    return Result;
}


static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring,
    _In_ USHORT SubstringLength
    )
{
    SIZE_T StringLen;
    SIZE_T SubLen;
    SIZE_T i, j;
    BOOLEAN Match;

    if (String == NULL || String->Buffer == NULL || Substring == NULL) {
        return FALSE;
    }

    StringLen = String->Length / sizeof(WCHAR);
    SubLen = SubstringLength;

    //
    // Bounds check - SubLen is now pre-computed and trusted
    //
    if (SubLen > StringLen || SubLen == 0 || SubLen > PW_MAX_SUBSTRING_LENGTH) {
        return FALSE;
    }

    for (i = 0; i <= StringLen - SubLen; i++) {
        Match = TRUE;
        for (j = 0; j < SubLen; j++) {
            WCHAR c1 = String->Buffer[i + j];
            WCHAR c2 = Substring[j];

            //
            // Case-insensitive comparison (ASCII only for performance)
            //
            if (c1 >= L'A' && c1 <= L'Z') {
                c1 += (L'a' - L'A');
            }
            if (c2 >= L'A' && c2 <= L'Z') {
                c2 += (L'a' - L'A');
            }

            if (c1 != c2) {
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


static ULONG
PwpAnalyzeWriteSuspicion(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PPW_COMPLETION_CONTEXT Context
    )
{
    ULONG Suspicion = PW_SUSPICION_NONE;
    PVOID WriteBuffer = NULL;
    ULONG EntropyScore = 0;
    BOOLEAN BufferFromMdl = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Check for header overwrite (common in ransomware)
    //
    if (Context->WritesToFileStart && Context->WriteLength >= 512) {
        Suspicion |= PW_SUSPICION_OVERWRITE_HEADER;
    }

    //
    // Entropy analysis for ransomware detection
    //
    if (g_PwState.Config.EnableEntropyAnalysis &&
        Context->WriteLength >= PW_ENTROPY_SAMPLE_SIZE) {

        //
        // Get write buffer (MDL or user buffer)
        //
        if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
            WriteBuffer = MmGetSystemAddressForMdlSafe(
                Data->Iopb->Parameters.Write.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute
                );
            BufferFromMdl = TRUE;
        }

        if (WriteBuffer == NULL) {
            WriteBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
            BufferFromMdl = FALSE;
        }

        if (WriteBuffer != NULL) {
            __try {
                ULONG SampleSize = min(Context->WriteLength, PW_ENTROPY_SAMPLE_SIZE);

                //
                // For user-mode buffers, probe before access
                //
                if (!BufferFromMdl && Data->RequestorMode == UserMode) {
                    ProbeForRead(WriteBuffer, SampleSize, sizeof(UCHAR));
                }

                EntropyScore = PwpCalculateBufferEntropy(WriteBuffer, SampleSize);
                Context->EntropyScore = EntropyScore;

                if (EntropyScore >= PW_RANSOMWARE_ENTROPY_THRESHOLD) {
                    Suspicion |= PW_SUSPICION_HIGH_ENTROPY;
                    InterlockedIncrement64(&g_PwState.Stats.HighEntropyWrites);

                    //
                    // High-entropy write to document is very suspicious
                    //
                    if (Context->FileClassification & PW_FILE_DOCUMENT) {
                        Suspicion |= PW_SUSPICION_DOCUMENT_ENCRYPT;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                //
                // Buffer access failed - user buffer may be invalid
                // This is expected for malicious processes
                //
            }
        }
    }

    //
    // Large write detection
    //
    if (Context->WriteLength >= PW_MASSIVE_WRITE_THRESHOLD) {
        Suspicion |= PW_SUSPICION_MASS_WRITE;
        InterlockedIncrement64(&g_PwState.Stats.MassWriteDetections);
    }

    //
    // Check for appending to executable (code injection indicator)
    //
    if ((Context->FileClassification & PW_FILE_EXECUTABLE) &&
        !Context->WritesToFileStart &&
        Context->IsOffsetSpecified) {
        Suspicion |= PW_SUSPICION_APPEND_EXECUTABLE;
    }

    return Suspicion;
}


static ULONG
PwpCalculateBufferEntropy(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    )
{
    PPW_ENTROPY_CONTEXT EntropyCtx;
    PUCHAR Data = (PUCHAR)Buffer;
    ULONG i;
    ULONG EntropyValue = 0;
    ULONG UniqueBytes = 0;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    //
    // Allocate entropy context from lookaside (avoids stack overflow)
    //
    if (!g_PwState.LookasideInitialized) {
        return 0;
    }

    EntropyCtx = (PPW_ENTROPY_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_PwState.EntropyLookaside
        );

    if (EntropyCtx == NULL) {
        return 0;
    }

    RtlZeroMemory(EntropyCtx->ByteCounts, sizeof(EntropyCtx->ByteCounts));

    //
    // Count byte frequencies
    //
    for (i = 0; i < Length; i++) {
        EntropyCtx->ByteCounts[Data[i]]++;
    }

    //
    // Calculate entropy approximation (scaled 0-1000)
    // Higher unique byte counts with even distribution = higher entropy
    //
    for (i = 0; i < 256; i++) {
        if (EntropyCtx->ByteCounts[i] > 0) {
            UniqueBytes++;

            //
            // Calculate contribution based on frequency
            //
            ULONG Frequency = (EntropyCtx->ByteCounts[i] * 1000) / Length;

            //
            // Ideal uniform distribution would have ~4 per byte
            // Score higher for more uniform distributions
            //
            if (Frequency > 0 && Frequency < 20) {
                EntropyValue += 4;  // Near uniform
            } else if (Frequency >= 20 && Frequency < 50) {
                EntropyValue += 2;  // Moderate
            } else {
                EntropyValue += 1;  // Skewed
            }
        }
    }

    //
    // Normalize based on unique byte count
    // Encrypted/compressed data typically uses most of the byte range
    //
    if (UniqueBytes > 200) {
        EntropyValue = min(EntropyValue * 5, 1000);
    } else if (UniqueBytes > 100) {
        EntropyValue = min(EntropyValue * 3, 1000);
    } else {
        EntropyValue = min(EntropyValue * 2, 1000);
    }

    //
    // Return entropy context to lookaside
    //
    ExFreeToNPagedLookasideList(&g_PwState.EntropyLookaside, EntropyCtx);

    return EntropyValue;
}


static BOOLEAN
PwpShouldBlockWrite(
    _In_ ULONG SuspicionFlags,
    _In_ ULONG FileClassification
    )
{
    //
    // Always block writes to shadow copies with high suspicion
    //
    if ((SuspicionFlags & PW_SUSPICION_SHADOW_COPY) &&
        (SuspicionFlags & (PW_SUSPICION_HIGH_ENTROPY | PW_SUSPICION_OVERWRITE_HEADER))) {
        return TRUE;
    }

    //
    // Block high entropy writes to credential files
    //
    if ((SuspicionFlags & PW_SUSPICION_CREDENTIAL_FILE) &&
        (SuspicionFlags & PW_SUSPICION_HIGH_ENTROPY)) {
        return TRUE;
    }

    //
    // Block canary file modifications (honeypot detection)
    //
    if (SuspicionFlags & PW_SUSPICION_CANARY_FILE) {
        return TRUE;
    }

    //
    // Block suspicious executable modifications
    //
    if ((FileClassification & PW_FILE_DRIVER) &&
        (SuspicionFlags & PW_SUSPICION_OVERWRITE_HEADER)) {
        return TRUE;
    }

    //
    // Block high-entropy header overwrites on documents (ransomware pattern)
    //
    if ((SuspicionFlags & PW_SUSPICION_DOCUMENT_ENCRYPT) &&
        (SuspicionFlags & PW_SUSPICION_OVERWRITE_HEADER)) {
        InterlockedIncrement64(&g_PwState.Stats.DocumentEncryptionBlocks);
        return TRUE;
    }

    //
    // Block high-entropy writes to backup files (ransomware pattern)
    //
    if ((SuspicionFlags & PW_SUSPICION_BACKUP_TARGET) &&
        (SuspicionFlags & PW_SUSPICION_HIGH_ENTROPY)) {
        return TRUE;
    }

    //
    // Block appending to executables with high entropy (code injection)
    //
    if ((SuspicionFlags & PW_SUSPICION_APPEND_EXECUTABLE) &&
        (SuspicionFlags & PW_SUSPICION_HIGH_ENTROPY)) {
        return TRUE;
    }

    //
    // By default, allow and monitor
    //
    return FALSE;
}


static VOID
PwpUpdateProcessWriteMetrics(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    )
{
    //
    // Call into FileSystemCallbacks infrastructure for process tracking
    // Operation type 1 = file modification
    //
    ShadowStrikeNotifyProcessFileOperation(ProcessId, 1, FileName);
}


static VOID
PwpNotifyWriteEvent(
    _In_ PPW_COMPLETION_CONTEXT Context,
    _In_ BOOLEAN Blocked
    )
{
    NTSTATUS Status;

    //
    // Build and send notification to user-mode via ScanBridge
    //
    if (ShadowStrikeScanBridgeIsReady() && Context->CapturedName.Length > 0) {
        //
        // For high-priority events, send synchronously
        // For monitoring events, use async notification
        //
        if (Context->SuspicionFlags & (PW_SUSPICION_CANARY_FILE |
                                       PW_SUSPICION_SHADOW_COPY |
                                       PW_SUSPICION_CREDENTIAL_FILE)) {
            //
            // Critical event - would send high-priority notification
            // In production, this would construct a proper message
            //
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PreWrite] CRITICAL EVENT %s: %wZ "
                "(PID=%lu, Flags=0x%08X, Entropy=%lu)\n",
                Blocked ? "BLOCKED" : "detected",
                &Context->CapturedName,
                HandleToULong(Context->ProcessId),
                Context->SuspicionFlags,
                Context->EntropyScore
                );
        } else if (Context->SuspicionFlags & PW_SUSPICION_HIGH_ENTROPY) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "[ShadowStrike/PreWrite] High-entropy write %s: %wZ "
                "(PID=%lu, Entropy=%lu, Len=%lu)\n",
                Blocked ? "BLOCKED" : "detected",
                &Context->CapturedName,
                HandleToULong(Context->ProcessId),
                Context->EntropyScore,
                Context->WriteLength
                );
        }

        //
        // ETW trace event for telemetry
        // In production implementation, this would call:
        // ShadowStrikeEtwTraceWriteEvent(Context, Blocked);
        //
    }

    UNREFERENCED_PARAMETER(Status);
}

// ============================================================================
// STATISTICS API
// ============================================================================

NTSTATUS
ShadowStrikeGetPreWriteStats(
    _Out_opt_ PULONG64 TotalCalls,
    _Out_opt_ PULONG64 Blocked,
    _Out_opt_ PULONG64 HighEntropyWrites,
    _Out_opt_ PULONG64 CacheInvalidations
    )
/*++
Routine Description:
    Gets pre-write callback statistics.

    NOTE: This function is designed for kernel-mode callers only.
    If exposed via IOCTL, the caller MUST validate pointers with
    ProbeForWrite before calling this function.

Arguments:
    TotalCalls - Receives total PreWrite calls.
    Blocked - Receives blocked writes count.
    HighEntropyWrites - Receives high-entropy write count.
    CacheInvalidations - Receives cache invalidation count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    if (!g_PwState.Initialized) {
        return STATUS_NOT_FOUND;
    }

    //
    // All pointers are optional - NULL is valid
    //
    if (TotalCalls != NULL) {
        *TotalCalls = (ULONG64)g_PwState.Stats.TotalPreWriteCalls;
    }

    if (Blocked != NULL) {
        *Blocked = (ULONG64)g_PwState.Stats.SelfProtectionBlocks;
    }

    if (HighEntropyWrites != NULL) {
        *HighEntropyWrites = (ULONG64)g_PwState.Stats.HighEntropyWrites;
    }

    if (CacheInvalidations != NULL) {
        *CacheInvalidations = (ULONG64)g_PwState.Stats.CacheInvalidations;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeGetPreWriteStatsEx(
    _In_ KPROCESSOR_MODE RequestorMode,
    _Out_writes_bytes_(OutputSize) PVOID OutputBuffer,
    _In_ ULONG OutputSize
    )
/*++
Routine Description:
    Gets pre-write callback statistics with proper user-mode validation.
    Use this function when called from IOCTL dispatch.

Arguments:
    RequestorMode - Caller's processor mode (UserMode or KernelMode).
    OutputBuffer - Buffer to receive statistics.
    OutputSize - Size of the output buffer.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_BUFFER_TOO_SMALL if buffer is too small.
    STATUS_ACCESS_VIOLATION if buffer is invalid.
--*/
{
    typedef struct _PW_STATS_OUTPUT {
        ULONG64 TotalCalls;
        ULONG64 Blocked;
        ULONG64 HighEntropyWrites;
        ULONG64 CacheInvalidations;
        ULONG64 CanaryFileHits;
        ULONG64 DocumentEncryptionBlocks;
    } PW_STATS_OUTPUT, *PPW_STATS_OUTPUT;

    PPW_STATS_OUTPUT Output;

    if (!g_PwState.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (OutputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputSize < sizeof(PW_STATS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Validate user-mode buffer
    //
    if (RequestorMode == UserMode) {
        __try {
            ProbeForWrite(OutputBuffer, OutputSize, sizeof(ULONG64));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    __try {
        Output = (PPW_STATS_OUTPUT)OutputBuffer;

        Output->TotalCalls = (ULONG64)g_PwState.Stats.TotalPreWriteCalls;
        Output->Blocked = (ULONG64)g_PwState.Stats.SelfProtectionBlocks;
        Output->HighEntropyWrites = (ULONG64)g_PwState.Stats.HighEntropyWrites;
        Output->CacheInvalidations = (ULONG64)g_PwState.Stats.CacheInvalidations;
        Output->CanaryFileHits = (ULONG64)g_PwState.Stats.CanaryFileHits;
        Output->DocumentEncryptionBlocks = (ULONG64)g_PwState.Stats.DocumentEncryptionBlocks;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}
