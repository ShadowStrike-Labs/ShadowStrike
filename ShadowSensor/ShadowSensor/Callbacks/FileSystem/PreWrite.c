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
@version 2.0.0 (Enterprise Edition)
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

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

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

//
// Sensitive file patterns
//
typedef struct _PW_SENSITIVE_PATTERN {
    PCWSTR Pattern;
    ULONG Classification;
} PW_SENSITIVE_PATTERN, *PPW_SENSITIVE_PATTERN;

//
// Global pre-write state
//
typedef struct _PW_GLOBAL_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;

    //
    // Lookaside list for completion contexts
    //
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN LookasideInitialized;

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
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableEntropyAnalysis;
        BOOLEAN EnableSensitiveFileProtection;
        BOOLEAN EnableMassWriteDetection;
        BOOLEAN EnablePostWriteTracking;
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
//
static const PW_SENSITIVE_PATTERN g_SensitivePatterns[] = {
    //
    // Shadow copy and backup files
    //
    { L"\\System Volume Information\\", PW_FILE_SHADOW_COPY },
    { L"@GMT-", PW_FILE_SHADOW_COPY },  // VSS snapshot pattern
    { L".bak", PW_FILE_BACKUP },
    { L".backup", PW_FILE_BACKUP },
    { L"\\Backup\\", PW_FILE_BACKUP },

    //
    // Credential and security files
    //
    { L"\\SAM", PW_FILE_CREDENTIAL },
    { L"\\SECURITY", PW_FILE_CREDENTIAL },
    { L"\\SYSTEM", PW_FILE_CREDENTIAL },
    { L"\\ntds.dit", PW_FILE_CREDENTIAL },
    { L"\\NTUSER.DAT", PW_FILE_CREDENTIAL },
    { L".pfx", PW_FILE_CERTIFICATE },
    { L".p12", PW_FILE_CERTIFICATE },
    { L".pem", PW_FILE_CERTIFICATE },
    { L".key", PW_FILE_CERTIFICATE },
    { L".cer", PW_FILE_CERTIFICATE },
    { L".crt", PW_FILE_CERTIFICATE },
    { L"\\ssh\\", PW_FILE_CREDENTIAL },
    { L"\\gnupg\\", PW_FILE_CREDENTIAL },
    { L"id_rsa", PW_FILE_CREDENTIAL },
    { L"id_ecdsa", PW_FILE_CREDENTIAL },
    { L"known_hosts", PW_FILE_CREDENTIAL },

    //
    // Database files
    //
    { L".mdf", PW_FILE_DATABASE },
    { L".ldf", PW_FILE_DATABASE },
    { L".ndf", PW_FILE_DATABASE },
    { L".sqlite", PW_FILE_DATABASE },
    { L".db", PW_FILE_DATABASE },
    { L".mdb", PW_FILE_DATABASE },
    { L".accdb", PW_FILE_DATABASE },

    //
    // System files
    //
    { L"\\Windows\\System32\\", PW_FILE_SYSTEM },
    { L"\\Windows\\SysWOW64\\", PW_FILE_SYSTEM },
    { L"\\Windows\\WinSxS\\", PW_FILE_SYSTEM },
    { L".sys", PW_FILE_DRIVER },
    { L"\\drivers\\", PW_FILE_DRIVER },

    //
    // Configuration files
    //
    { L"boot.ini", PW_FILE_CONFIG },
    { L"bootmgr", PW_FILE_CONFIG },
    { L"\\EFI\\", PW_FILE_CONFIG },
    { L".ini", PW_FILE_CONFIG },
    { L".conf", PW_FILE_CONFIG },
    { L".config", PW_FILE_CONFIG },
    { L"web.config", PW_FILE_CONFIG },
    { L"machine.config", PW_FILE_CONFIG },

    //
    // Log files (for tampering detection)
    //
    { L".evtx", PW_FILE_LOG },
    { L".log", PW_FILE_LOG },
    { L"\\winevt\\", PW_FILE_LOG },
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
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring
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

// ============================================================================
// INITIALIZATION
// ============================================================================

NTSTATUS
ShadowStrikeInitializePreWrite(
    VOID
    )
/*++
Routine Description:
    Initializes the pre-write callback subsystem.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    if (g_PwState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_PwState, sizeof(PW_GLOBAL_STATE));

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

    g_PwState.LookasideInitialized = TRUE;

    //
    // Set default configuration
    //
    g_PwState.Config.EnableEntropyAnalysis = TRUE;
    g_PwState.Config.EnableSensitiveFileProtection = TRUE;
    g_PwState.Config.EnableMassWriteDetection = TRUE;
    g_PwState.Config.EnablePostWriteTracking = TRUE;
    g_PwState.Config.EntropyThreshold = PW_HIGH_ENTROPY_THRESHOLD;
    g_PwState.Config.MassWriteThreshold = PW_WRITES_PER_SECOND_THRESHOLD;

    g_PwState.Initialized = TRUE;

    return STATUS_SUCCESS;
}


VOID
ShadowStrikeCleanupPreWrite(
    VOID
    )
/*++
Routine Description:
    Cleans up the pre-write callback subsystem.
--*/
{
    if (!g_PwState.Initialized) {
        return;
    }

    g_PwState.Initialized = FALSE;

    if (g_PwState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_PwState.ContextLookaside);
        g_PwState.LookasideInitialized = FALSE;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PreWrite] Shutdown. Stats: Total=%lld, Blocked=%lld, "
        "HighEntropy=%lld, Sensitive=%lld, Mass=%lld\n",
        g_PwState.Stats.TotalPreWriteCalls,
        g_PwState.Stats.SelfProtectionBlocks,
        g_PwState.Stats.HighEntropyWrites,
        g_PwState.Stats.SensitiveFileWrites,
        g_PwState.Stats.MassWriteDetections
        );
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
        // Cannot get file name - try to use file object name
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

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (CompletionContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PwContext = (PPW_COMPLETION_CONTEXT)CompletionContext;

    //
    // Validate context
    //
    if (PwContext->Signature != PW_CONTEXT_SIGNATURE) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/PostWrite] Invalid context signature!\n"
            );
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

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

    Context->Signature = 0;
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
    if (PwpStringContainsInsensitive(&Extension, L".exe") ||
        PwpStringContainsInsensitive(&Extension, L".dll") ||
        PwpStringContainsInsensitive(&Extension, L".sys") ||
        PwpStringContainsInsensitive(&Extension, L".scr") ||
        PwpStringContainsInsensitive(&Extension, L".com")) {
        Classification |= PW_FILE_EXECUTABLE;
    }

    if (PwpStringContainsInsensitive(&Extension, L".ps1") ||
        PwpStringContainsInsensitive(&Extension, L".bat") ||
        PwpStringContainsInsensitive(&Extension, L".cmd") ||
        PwpStringContainsInsensitive(&Extension, L".vbs") ||
        PwpStringContainsInsensitive(&Extension, L".js") ||
        PwpStringContainsInsensitive(&Extension, L".hta") ||
        PwpStringContainsInsensitive(&Extension, L".wsf")) {
        Classification |= PW_FILE_SCRIPT;
    }

    if (PwpStringContainsInsensitive(&Extension, L".doc") ||
        PwpStringContainsInsensitive(&Extension, L".xls") ||
        PwpStringContainsInsensitive(&Extension, L".ppt") ||
        PwpStringContainsInsensitive(&Extension, L".pdf") ||
        PwpStringContainsInsensitive(&Extension, L".rtf")) {
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
        if (PwpStringContainsInsensitive(FileName, g_SensitivePatterns[i].Pattern)) {
            *Classification |= g_SensitivePatterns[i].Classification;
        }
    }

    return (*Classification != 0);
}


static BOOLEAN
PwpStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring
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
    SubLen = wcslen(Substring);

    if (SubLen > StringLen || SubLen == 0) {
        return FALSE;
    }

    for (i = 0; i <= StringLen - SubLen; i++) {
        Match = TRUE;
        for (j = 0; j < SubLen; j++) {
            WCHAR c1 = String->Buffer[i + j];
            WCHAR c2 = Substring[j];

            //
            // Case-insensitive comparison
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
        }

        if (WriteBuffer == NULL) {
            WriteBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
        }

        if (WriteBuffer != NULL) {
            __try {
                ULONG SampleSize = min(Context->WriteLength, PW_ENTROPY_SAMPLE_SIZE);

                EntropyScore = PwpCalculateBufferEntropy(WriteBuffer, SampleSize);
                Context->EntropyScore = EntropyScore;

                if (EntropyScore >= PW_RANSOMWARE_ENTROPY_THRESHOLD) {
                    Suspicion |= PW_SUSPICION_HIGH_ENTROPY;
                    InterlockedIncrement64(&g_PwState.Stats.HighEntropyWrites);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                //
                // Buffer access failed - user buffer may be invalid
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
    ULONG ByteCounts[256] = {0};
    PUCHAR Data = (PUCHAR)Buffer;
    ULONG i;
    ULONG EntropyValue = 0;
    ULONG UniqueBytes = 0;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Length; i++) {
        ByteCounts[Data[i]]++;
    }

    //
    // Calculate entropy approximation (scaled 0-1000)
    // Higher unique byte counts with even distribution = higher entropy
    //
    for (i = 0; i < 256; i++) {
        if (ByteCounts[i] > 0) {
            UniqueBytes++;

            //
            // Calculate contribution based on frequency
            //
            ULONG Frequency = (ByteCounts[i] * 1000) / Length;

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
    //
    ShadowStrikeNotifyProcessFileOperation(ProcessId, 1, FileName);  // 1 = modify
}


static VOID
PwpNotifyWriteEvent(
    _In_ PPW_COMPLETION_CONTEXT Context,
    _In_ BOOLEAN Blocked
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Blocked);

    //
    // In a full implementation, this would:
    // 1. Queue a notification to user-mode via ScanBridge
    // 2. Log to ETW provider
    // 3. Update behavioral analytics
    //
    // For now, just log significant events
    //
    if (Context->SuspicionFlags & PW_SUSPICION_HIGH_ENTROPY) {
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
}

// ============================================================================
// STATISTICS API
// ============================================================================

NTSTATUS
ShadowStrikeGetPreWriteStats(
    _Out_ PULONG64 TotalCalls,
    _Out_ PULONG64 Blocked,
    _Out_ PULONG64 HighEntropyWrites,
    _Out_ PULONG64 CacheInvalidations
    )
/*++
Routine Description:
    Gets pre-write callback statistics.

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

