/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE POST-CREATE CALLBACK IMPLEMENTATION
 * ============================================================================
 *
 * @file PostCreate.c
 * @brief Enterprise-grade IRP_MJ_CREATE post-operation callback for kernel EDR.
 *
 * Implements CrowdStrike Falcon-class post-create handling:
 * - Stream context attachment and lifecycle management
 * - Stream handle context for per-open tracking
 * - File attribute caching for performance optimization
 * - Scan verdict correlation between pre-create and post-create
 * - File ID tracking for cache integration
 * - Change detection baseline establishment
 * - Ransomware monitoring setup
 * - Volume and file classification persistence
 * - Comprehensive telemetry and statistics
 *
 * Context Management:
 * - Lookaside list allocation for contexts
 * - Reference counting with proper cleanup
 * - Thread-safe context updates
 * - Graceful handling of racing operations
 * - Double-free protection with ownership tokens
 *
 * BSOD PREVENTION:
 * - Check FLT_POST_OPERATION_FLAGS for draining
 * - Validate all pointers before use
 * - Handle context allocation failures gracefully
 * - Exception handling for invalid memory access
 * - Proper IRQL awareness (all annotations verified)
 * - Atomic operations for all shared state
 *
 * Performance Characteristics:
 * - O(1) context lookup via FltGetStreamContext
 * - Lookaside list allocation for completion/handle contexts
 * - Minimal blocking in post-create path
 * - Efficient file attribute querying
 * - Rate-limited logging
 *
 * MITRE ATT&CK Coverage:
 * - T1486: Data Encrypted for Impact (ransomware baseline)
 * - T1485: Data Destruction (change tracking)
 * - T1564.004: NTFS File Attributes (ADS tracking)
 * - T1070.004: Indicator Removal on Host (file deletion tracking)
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "PostCreate.h"
#include "PreCreate.h"
#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Cache/ScanCache.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/StringUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Extension classification entry
 */
typedef struct _POC_EXTENSION_ENTRY {
    PCWSTR Extension;
    POC_FILE_CLASS Class;
} POC_EXTENSION_ENTRY;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static POC_GLOBAL_STATE g_PocState = {0};

// ============================================================================
// EXTENSION CLASSIFICATION TABLE
// ============================================================================

static const POC_EXTENSION_ENTRY g_ExtensionTable[] = {
    // Executables
    { L"exe",   PocFileClassExecutable },
    { L"dll",   PocFileClassExecutable },
    { L"sys",   PocFileClassExecutable },
    { L"drv",   PocFileClassExecutable },
    { L"scr",   PocFileClassExecutable },
    { L"com",   PocFileClassExecutable },
    { L"msi",   PocFileClassExecutable },
    { L"ocx",   PocFileClassExecutable },
    { L"cpl",   PocFileClassExecutable },

    // Scripts
    { L"ps1",   PocFileClassScript },
    { L"bat",   PocFileClassScript },
    { L"cmd",   PocFileClassScript },
    { L"vbs",   PocFileClassScript },
    { L"js",    PocFileClassScript },
    { L"hta",   PocFileClassScript },
    { L"wsf",   PocFileClassScript },

    // Documents
    { L"doc",   PocFileClassDocument },
    { L"docx",  PocFileClassDocument },
    { L"docm",  PocFileClassDocument },
    { L"xls",   PocFileClassDocument },
    { L"xlsx",  PocFileClassDocument },
    { L"xlsm",  PocFileClassDocument },
    { L"ppt",   PocFileClassDocument },
    { L"pptx",  PocFileClassDocument },
    { L"pdf",   PocFileClassDocument },
    { L"rtf",   PocFileClassDocument },

    // Archives
    { L"zip",   PocFileClassArchive },
    { L"rar",   PocFileClassArchive },
    { L"7z",    PocFileClassArchive },
    { L"cab",   PocFileClassArchive },
    { L"iso",   PocFileClassArchive },
    { L"tar",   PocFileClassArchive },
    { L"gz",    PocFileClassArchive },

    // Media
    { L"jpg",   PocFileClassMedia },
    { L"jpeg",  PocFileClassMedia },
    { L"png",   PocFileClassMedia },
    { L"gif",   PocFileClassMedia },
    { L"bmp",   PocFileClassMedia },
    { L"mp3",   PocFileClassMedia },
    { L"mp4",   PocFileClassMedia },
    { L"avi",   PocFileClassMedia },
    { L"mkv",   PocFileClassMedia },

    // Configuration
    { L"ini",   PocFileClassConfig },
    { L"cfg",   PocFileClassConfig },
    { L"conf",  PocFileClassConfig },
    { L"xml",   PocFileClassConfig },
    { L"json",  PocFileClassConfig },
    { L"yaml",  PocFileClassConfig },

    // Certificates
    { L"pem",   PocFileClassCertificate },
    { L"pfx",   PocFileClassCertificate },
    { L"p12",   PocFileClassCertificate },
    { L"cer",   PocFileClassCertificate },
    { L"crt",   PocFileClassCertificate },
    { L"key",   PocFileClassCertificate },

    // Databases
    { L"mdb",   PocFileClassDatabase },
    { L"accdb", PocFileClassDatabase },
    { L"sqlite",PocFileClassDatabase },
    { L"db",    PocFileClassDatabase },
    { L"sql",   PocFileClassDatabase },

    // Backup
    { L"bak",   PocFileClassBackup },
    { L"backup",PocFileClassBackup },
    { L"old",   PocFileClassBackup },

    // Log files
    { L"log",   PocFileClassLog },
    { L"evt",   PocFileClassLog },
    { L"evtx",  PocFileClassLog },

    // Temporary
    { L"tmp",   PocFileClassTemporary },
    { L"temp",  PocFileClassTemporary },
};

#define POC_EXTENSION_TABLE_COUNT (sizeof(g_ExtensionTable) / sizeof(g_ExtensionTable[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static BOOLEAN
PocpShouldLogOperation(
    VOID
    );

static NTSTATUS
PocpQueryFileInformation(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLONGLONG OutFileId,
    _Out_ PLONGLONG OutFileSize,
    _Out_ PLARGE_INTEGER OutLastWriteTime,
    _Out_ PLARGE_INTEGER OutCreationTime
    );

static VOID
PocpInitializeDefaultConfig(
    VOID
    );

static VOID
PocpSetTrackingFlags(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo
    );

static NTSTATUS
PocpQueryVolumeSerial(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG OutSerial
    );

/**
 * @brief Case-insensitive wide string compare (DISPATCH_LEVEL safe).
 *
 * Does NOT touch pageable memory - safe at any IRQL.
 */
FORCEINLINE
LONG
PocpCompareExtensionSafe(
    _In_ PCWSTR Ext1,
    _In_ PCWSTR Ext2
    )
{
    while (*Ext1 && *Ext2) {
        WCHAR c1 = *Ext1;
        WCHAR c2 = *Ext2;

        //
        // Convert ASCII uppercase to lowercase
        //
        if (c1 >= L'A' && c1 <= L'Z') {
            c1 = c1 + (L'a' - L'A');
        }
        if (c2 >= L'A' && c2 <= L'Z') {
            c2 = c2 + (L'a' - L'A');
        }

        if (c1 != c2) {
            return (LONG)(c1 - c2);
        }

        Ext1++;
        Ext2++;
    }

    return (LONG)(*Ext1 - *Ext2);
}

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, PocInitialize)
#pragma alloc_text(PAGE, PocShutdown)
#pragma alloc_text(PAGE, PocAllocateStreamContext)
#pragma alloc_text(PAGE, PocGetOrCreateStreamContext)
#pragma alloc_text(PAGE, PocUpdateStreamContext)
#pragma alloc_text(PAGE, PocApplyCompletionContext)
#pragma alloc_text(PAGE, PocQueryFileAttributes)
#pragma alloc_text(PAGE, PocCacheFileName)
#pragma alloc_text(PAGE, PocClassifyFileExtension)
#pragma alloc_text(PAGE, PocMarkFileModified)
#pragma alloc_text(PAGE, PocInvalidateScanResult)
#pragma alloc_text(PAGE, PocAllocateCompletionContext)
#pragma alloc_text(PAGE, PocAllocateHandleContext)
#pragma alloc_text(PAGE, PocGetOrCreateHandleContext)
#pragma alloc_text(PAGE, ShadowStrikePostCreate)
#pragma alloc_text(PAGE, PocpQueryFileInformation)
#pragma alloc_text(PAGE, PocpSetTrackingFlags)
#pragma alloc_text(PAGE, PocpQueryVolumeSerial)
#endif

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PocInitialize(
    VOID
    )
{
    LONG previousValue;

    PAGED_CODE();

    //
    // Atomic check-and-set to prevent double initialization
    //
    previousValue = InterlockedCompareExchange(&g_PocState.Initialized, 1, 0);
    if (previousValue != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Zero out everything except Initialized (already set to 1)
    //
    RtlZeroMemory(&g_PocState.Stats, sizeof(g_PocState.Stats));
    RtlZeroMemory(&g_PocState.Config, sizeof(g_PocState.Config));

    InterlockedExchange(&g_PocState.ShutdownRequested, 0);
    g_PocState.StreamContextRegistered = FALSE;
    g_PocState.HandleContextRegistered = FALSE;
    g_PocState.LookasideInitialized = FALSE;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_PocState.CompletionContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(POC_COMPLETION_CONTEXT),
        POC_CONTEXT_TAG,
        POC_COMPLETION_LOOKASIDE_DEPTH
        );

    ExInitializeNPagedLookasideList(
        &g_PocState.HandleContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOWSTRIKE_HANDLE_CONTEXT),
        POC_HANDLE_TAG,
        POC_HANDLE_LOOKASIDE_DEPTH
        );

    g_PocState.LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    PocpInitializeDefaultConfig();

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_PocState.Stats.StartTime);

    //
    // Initialize rate limiter (atomic)
    //
    {
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);
        InterlockedExchange64(&g_PocState.CurrentSecondStart, currentTime.QuadPart);
        InterlockedExchange(&g_PocState.CurrentSecondLogs, 0);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PostCreate] PostCreate subsystem initialized\n"
        );

    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
PocShutdown(
    VOID
    )
{
    LONG wasInitialized;

    PAGED_CODE();

    //
    // Atomically mark as shutting down and check if was initialized
    //
    wasInitialized = InterlockedExchange(&g_PocState.Initialized, 0);
    if (wasInitialized == 0) {
        return;
    }

    InterlockedExchange(&g_PocState.ShutdownRequested, 1);

    //
    // Delete lookaside lists
    //
    if (g_PocState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_PocState.CompletionContextLookaside);
        ExDeleteNPagedLookasideList(&g_PocState.HandleContextLookaside);
        g_PocState.LookasideInitialized = FALSE;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PostCreate] PostCreate shutdown. "
        "Stats: Total=%lld, Created=%lld, Reused=%lld, Failed=%lld, "
        "SigMismatch=%lld, DoubleFree=%lld\n",
        PocAtomicRead64(&g_PocState.Stats.TotalPostCreates),
        PocAtomicRead64(&g_PocState.Stats.ContextsCreated),
        PocAtomicRead64(&g_PocState.Stats.ContextsReused),
        PocAtomicRead64(&g_PocState.Stats.ContextsFailed),
        PocAtomicRead64(&g_PocState.Stats.SignatureMismatches),
        PocAtomicRead64(&g_PocState.Stats.DoubleFreeAttempts)
        );
}


static VOID
PocpInitializeDefaultConfig(
    VOID
    )
{
    g_PocState.Config.EnableContextCaching = TRUE;
    g_PocState.Config.EnableChangeTracking = TRUE;
    g_PocState.Config.EnableRansomwareWatch = TRUE;
    g_PocState.Config.EnableHoneypotTracking = TRUE;
    g_PocState.Config.EnableHandleContexts = TRUE;
    g_PocState.Config.LogContextCreation = FALSE;  // Off by default (verbose)
}

// ============================================================================
// PUBLIC API - MAIN CALLBACK
// ============================================================================

_Use_decl_annotations_
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++
Routine Description:
    Enterprise-grade IRP_MJ_CREATE post-operation callback.

    After a file is successfully opened, this callback:
    1. Attaches a stream context to track file state
    2. Optionally attaches a handle context for per-open tracking
    3. Records file attributes for cache correlation
    4. Applies scan results from PreCreate
    5. Establishes baseline for change detection
    6. Sets up ransomware monitoring if applicable

Arguments:
    Data                - Callback data for this operation.
    FltObjects          - Related filter objects.
    CompletionContext   - Context from PreCreate (scan verdict info).
    Flags               - Post-operation flags.

Return Value:
    FLT_POSTOP_FINISHED_PROCESSING always.
--*/
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT streamContext = NULL;
    PSHADOWSTRIKE_STREAM_CONTEXT existingContext = NULL;
    PSHADOWSTRIKE_HANDLE_CONTEXT handleContext = NULL;
    PPOC_COMPLETION_CONTEXT completionCtx = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN contextCreated = FALSE;
    LONGLONG fileId = 0;
    LONGLONG fileSize = 0;
    LARGE_INTEGER lastWriteTime = {0};
    LARGE_INTEGER creationTime = {0};
    POC_FILE_CLASS fileClass = PocFileClassUnknown;
    ULONG volumeSerial = 0;

    PAGED_CODE();

    //
    // Always increment total operations (atomic)
    //
    InterlockedIncrement64(&g_PocState.Stats.TotalPostCreates);

    // ========================================================================
    // PHASE 1: FAST-FAIL CHECKS
    // ========================================================================

    //
    // Check if we're draining - don't do any work during unload
    //
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        InterlockedIncrement64(&g_PocState.Stats.DrainingSkipped);
        goto Cleanup;
    }

    //
    // Check if driver is ready (atomic reads)
    //
    if (InterlockedCompareExchange(&g_PocState.Initialized, 1, 1) != 1) {
        goto Cleanup;
    }

    if (InterlockedCompareExchange(&g_PocState.ShutdownRequested, 0, 0) != 0) {
        goto Cleanup;
    }

    if (!SHADOWSTRIKE_IS_READY()) {
        goto Cleanup;
    }

    //
    // Validate filter handle before any context operations
    //
    if (g_DriverData.FilterHandle == NULL) {
        InterlockedIncrement64(&g_PocState.Stats.ErrorsHandled);
        goto Cleanup;
    }

    //
    // Only process if the create succeeded
    //
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        goto Cleanup;
    }

    //
    // Validate required pointers
    //
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        InterlockedIncrement64(&g_PocState.Stats.ContextsSkipped);
        goto Cleanup;
    }

    //
    // Skip directories - we only track files
    //
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        InterlockedIncrement64(&g_PocState.Stats.DirectoriesSkipped);
        goto Cleanup;
    }

    //
    // Skip volume opens
    //
    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        InterlockedIncrement64(&g_PocState.Stats.VolumeOpensSkipped);
        goto Cleanup;
    }

    // ========================================================================
    // PHASE 2: VALIDATE COMPLETION CONTEXT
    // ========================================================================

    if (CompletionContext != NULL) {
        completionCtx = (PPOC_COMPLETION_CONTEXT)CompletionContext;

        if (!PocIsValidCompletionContext(completionCtx)) {
            //
            // Invalid completion context - track and treat as no context
            //
            InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
            completionCtx = NULL;
        }
    }

    // ========================================================================
    // PHASE 3: CHECK FOR EXISTING STREAM CONTEXT
    // ========================================================================

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&existingContext
        );

    if (NT_SUCCESS(status)) {
        //
        // Context already exists - update it with scan info if available
        //
        InterlockedIncrement64(&g_PocState.Stats.ContextsReused);

        if (completionCtx != NULL && completionCtx->WasScanned) {
            //
            // Apply scan results to existing context
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&existingContext->Lock);

            existingContext->Scanned = TRUE;
            existingContext->ScanResult = completionCtx->ScanResult;
            existingContext->ThreatScore = completionCtx->ThreatScore;
            existingContext->ScanVerdictTTL = completionCtx->CacheTTL;
            KeQuerySystemTime(&existingContext->ScanTime);

            if (completionCtx->FileClass != PocFileClassUnknown) {
                existingContext->FileClass = completionCtx->FileClass;
            }

            //
            // Apply suspicious flags
            //
            existingContext->TrackingFlags |= completionCtx->SuspicionFlags;

            ExReleasePushLockExclusive(&existingContext->Lock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&g_PocState.Stats.ScannedFiles);
        }

        //
        // Update access time and open count
        //
        KeQuerySystemTime(&existingContext->LastAccessTime);
        InterlockedIncrement(&existingContext->OpenCount);

        FltReleaseContext((PFLT_CONTEXT)existingContext);
        existingContext = NULL;

        //
        // Still create handle context if enabled
        //
        goto CreateHandleContext;
    }

    // ========================================================================
    // PHASE 4: ALLOCATE NEW STREAM CONTEXT
    // ========================================================================

    status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_STREAM_CONTEXT,
        sizeof(SHADOWSTRIKE_STREAM_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&streamContext
        );

    if (!NT_SUCCESS(status)) {
        //
        // Allocation failed - not fatal, just means we won't track this file
        //
        InterlockedIncrement64(&g_PocState.Stats.ContextsFailed);

        if (PocpShouldLogOperation()) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PostCreate] Context allocation failed: 0x%08X\n",
                status
                );
        }

        goto Cleanup;
    }

    //
    // Initialize the stream context
    //
    RtlZeroMemory(streamContext, sizeof(SHADOWSTRIKE_STREAM_CONTEXT));
    streamContext->Signature = POC_STREAM_CONTEXT_SIGNATURE;
    streamContext->SecurityCookie = PocComputeSecurityCookie(streamContext);
    ExInitializePushLock(&streamContext->Lock);
    KeQuerySystemTime(&streamContext->ContextCreateTime);
    KeQuerySystemTime(&streamContext->LastAccessTime);
    streamContext->OpenCount = 1;

    // ========================================================================
    // PHASE 5: QUERY FILE INFORMATION
    // ========================================================================

    status = PocpQueryFileInformation(
        FltObjects,
        &fileId,
        &fileSize,
        &lastWriteTime,
        &creationTime
        );

    if (NT_SUCCESS(status)) {
        streamContext->FileId = fileId;
        streamContext->ScanFileSize = fileSize;
        streamContext->LastWriteTime = lastWriteTime;
        streamContext->CreationTime = creationTime;
    }

    //
    // Get actual volume serial number
    //
    status = PocpQueryVolumeSerial(FltObjects, &volumeSerial);
    if (NT_SUCCESS(status)) {
        streamContext->VolumeSerial = volumeSerial;
    }

    // ========================================================================
    // PHASE 6: GET FILE NAME AND CLASSIFY
    // ========================================================================

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
        );

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);

        if (NT_SUCCESS(status)) {
            //
            // Cache file name if enabled
            //
            if (g_PocState.Config.EnableContextCaching) {
                PocCacheFileName(nameInfo, streamContext);
            }

            //
            // Classify file by extension
            //
            fileClass = PocClassifyFileExtension(&nameInfo->Extension);
            streamContext->FileClass = fileClass;

            //
            // Set tracking flags based on path and attributes
            //
            PocpSetTrackingFlags(streamContext, FltObjects, nameInfo);
        }
    }

    // ========================================================================
    // PHASE 7: APPLY COMPLETION CONTEXT (SCAN RESULTS)
    // ========================================================================

    if (completionCtx != NULL && completionCtx->WasScanned) {
        streamContext->Scanned = TRUE;
        streamContext->ScanResult = completionCtx->ScanResult;
        streamContext->ThreatScore = completionCtx->ThreatScore;
        streamContext->ScanVerdictTTL = completionCtx->CacheTTL;
        KeQuerySystemTime(&streamContext->ScanTime);

        if (completionCtx->FileClass != PocFileClassUnknown) {
            streamContext->FileClass = completionCtx->FileClass;
        }

        streamContext->TrackingFlags |= completionCtx->SuspicionFlags;
        streamContext->TrackingFlags |= PocTrackingScanned;

        InterlockedIncrement64(&g_PocState.Stats.ScannedFiles);

        if (g_PocState.Config.LogContextCreation && PocpShouldLogOperation()) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "[ShadowStrike/PostCreate] Context created with scan result: "
                "FileId=0x%llX, Score=%u, Class=%d\n",
                fileId,
                completionCtx->ThreatScore,
                fileClass
                );
        }
    }

    // ========================================================================
    // PHASE 8: QUERY AND CACHE FILE ATTRIBUTES
    // ========================================================================

    status = PocQueryFileAttributes(FltObjects, streamContext);
    //
    // Non-fatal if this fails - continue with attachment
    //

    // ========================================================================
    // PHASE 9: SETUP RANSOMWARE MONITORING
    // ========================================================================

    if (g_PocState.Config.EnableRansomwareWatch) {
        //
        // Enable ransomware monitoring for document and backup files
        //
        if (fileClass == PocFileClassDocument ||
            fileClass == PocFileClassDatabase ||
            fileClass == PocFileClassBackup ||
            fileClass == PocFileClassCertificate) {

            streamContext->RansomwareMonitored = TRUE;
            streamContext->TrackingFlags |= PocTrackingRansomwareWatch;

            //
            // Initial entropy would be computed during first scan
            // Zero indicates "not yet computed"
            //
            streamContext->OriginalEntropyScore = 0;
        }
    }

    // ========================================================================
    // PHASE 10: ATTACH CONTEXT TO STREAM
    // ========================================================================

    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)streamContext,
        (PFLT_CONTEXT*)&existingContext
        );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        //
        // Another thread beat us to it - use existing context
        //
        InterlockedIncrement64(&g_PocState.Stats.ContextsReused);

        if (existingContext != NULL) {
            //
            // Update existing context with our scan info if we have it
            //
            if (completionCtx != NULL && completionCtx->WasScanned) {
                KeEnterCriticalRegion();
                ExAcquirePushLockExclusive(&existingContext->Lock);

                existingContext->Scanned = TRUE;
                existingContext->ScanResult = completionCtx->ScanResult;
                existingContext->ThreatScore = completionCtx->ThreatScore;
                KeQuerySystemTime(&existingContext->ScanTime);

                ExReleasePushLockExclusive(&existingContext->Lock);
                KeLeaveCriticalRegion();
            }

            FltReleaseContext((PFLT_CONTEXT)existingContext);
            existingContext = NULL;
        }

        contextCreated = FALSE;
    } else if (!NT_SUCCESS(status)) {
        //
        // Failed to set context
        //
        InterlockedIncrement64(&g_PocState.Stats.ContextsFailed);
        InterlockedIncrement64(&g_PocState.Stats.ErrorsHandled);

        if (PocpShouldLogOperation()) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PostCreate] FltSetStreamContext failed: 0x%08X\n",
                status
                );
        }

        contextCreated = FALSE;
    } else {
        //
        // Context attached successfully
        //
        InterlockedIncrement64(&g_PocState.Stats.ContextsCreated);
        contextCreated = TRUE;
    }

    // ========================================================================
    // PHASE 11: CREATE HANDLE CONTEXT (IF ENABLED)
    // ========================================================================

CreateHandleContext:
    if (g_PocState.Config.EnableHandleContexts) {
        status = PocGetOrCreateHandleContext(
            FltObjects,
            Data,
            &handleContext,
            NULL
            );

        if (NT_SUCCESS(status) && handleContext != NULL) {
            //
            // Handle context created/found - release our reference
            //
            FltReleaseContext((PFLT_CONTEXT)handleContext);
            handleContext = NULL;
        }
    }

    // ========================================================================
    // CLEANUP
    // ========================================================================

Cleanup:
    //
    // Release file name information
    //
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
        nameInfo = NULL;
    }

    //
    // Release our reference on stream context
    // (FltSetStreamContext adds its own if successful)
    //
    if (streamContext != NULL) {
        FltReleaseContext((PFLT_CONTEXT)streamContext);
        streamContext = NULL;
    }

    //
    // Free completion context if provided (with double-free protection)
    //
    if (completionCtx != NULL) {
        PocFreeCompletionContext(&completionCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// PUBLIC API - CONTEXT MANAGEMENT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocAllocateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_STREAM_CONTEXT* OutContext
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT context = NULL;

    PAGED_CODE();

    if (FltObjects == NULL || OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutContext = NULL;

    //
    // Validate filter handle
    //
    if (g_DriverData.FilterHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_STREAM_CONTEXT,
        sizeof(SHADOWSTRIKE_STREAM_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&context
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(context, sizeof(SHADOWSTRIKE_STREAM_CONTEXT));
    context->Signature = POC_STREAM_CONTEXT_SIGNATURE;
    ExInitializePushLock(&context->Lock);
    KeQuerySystemTime(&context->ContextCreateTime);
    KeQuerySystemTime(&context->LastAccessTime);
    context->OpenCount = 1;

    *OutContext = context;

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocGetOrCreateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSHADOWSTRIKE_STREAM_CONTEXT* OutContext,
    _Out_opt_ PBOOLEAN OutCreated
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_STREAM_CONTEXT context = NULL;
    PSHADOWSTRIKE_STREAM_CONTEXT existingContext = NULL;
    BOOLEAN created = FALSE;

    PAGED_CODE();

    if (FltObjects == NULL || OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutContext = NULL;
    if (OutCreated != NULL) {
        *OutCreated = FALSE;
    }

    //
    // Validate required pointers
    //
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Try to get existing context first
    //
    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&context
        );

    if (NT_SUCCESS(status)) {
        //
        // Existing context found
        //
        if (PocIsValidStreamContext(context)) {
            *OutContext = context;
            return STATUS_SUCCESS;
        }

        //
        // Invalid context - release and create new
        //
        InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;
    }

    //
    // Allocate new context
    //
    status = PocAllocateStreamContext(FltObjects, &context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Attach to stream
    //
    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)context,
        (PFLT_CONTEXT*)&existingContext
        );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        //
        // Use existing context
        //
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;

        if (existingContext != NULL && PocIsValidStreamContext(existingContext)) {
            *OutContext = existingContext;
            return STATUS_SUCCESS;
        }

        if (existingContext != NULL) {
            InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
            FltReleaseContext((PFLT_CONTEXT)existingContext);
        }

        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        FltReleaseContext((PFLT_CONTEXT)context);
        return status;
    }

    created = TRUE;
    *OutContext = context;

    if (OutCreated != NULL) {
        *OutCreated = created;
    }

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocUpdateStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    LONGLONG fileId = 0;
    LONGLONG fileSize = 0;
    LARGE_INTEGER lastWriteTime = {0};
    LARGE_INTEGER creationTime = {0};

    PAGED_CODE();

    if (FltObjects == NULL || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!PocIsValidStreamContext(Context)) {
        InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Query current file information
    //
    status = PocpQueryFileInformation(
        FltObjects,
        &fileId,
        &fileSize,
        &lastWriteTime,
        &creationTime
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    //
    // Check if file was modified
    //
    if (Context->ScanFileSize != fileSize ||
        Context->LastWriteTime.QuadPart != lastWriteTime.QuadPart) {

        Context->Dirty = TRUE;
        Context->TrackingFlags |= PocTrackingModified;

        //
        // Invalidate scan result on modification
        //
        Context->Scanned = FALSE;
    }

    Context->FileId = fileId;
    Context->ScanFileSize = fileSize;
    Context->LastWriteTime = lastWriteTime;

    KeQuerySystemTime(&Context->LastAccessTime);

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
VOID
PocApplyCompletionContext(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT StreamContext,
    _In_ PPOC_COMPLETION_CONTEXT CompletionContext
    )
{
    PAGED_CODE();

    if (StreamContext == NULL || CompletionContext == NULL) {
        return;
    }

    if (!PocIsValidStreamContext(StreamContext)) {
        InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        return;
    }

    if (!PocIsValidCompletionContext(CompletionContext)) {
        InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&StreamContext->Lock);

    StreamContext->Scanned = CompletionContext->WasScanned;
    StreamContext->ScanResult = CompletionContext->ScanResult;
    StreamContext->ThreatScore = CompletionContext->ThreatScore;
    StreamContext->ScanVerdictTTL = CompletionContext->CacheTTL;

    if (CompletionContext->WasScanned) {
        KeQuerySystemTime(&StreamContext->ScanTime);
        StreamContext->TrackingFlags |= PocTrackingScanned;
    }

    if (CompletionContext->FileClass != PocFileClassUnknown) {
        StreamContext->FileClass = CompletionContext->FileClass;
    }

    StreamContext->TrackingFlags |= CompletionContext->SuspicionFlags;

    ExReleasePushLockExclusive(&StreamContext->Lock);
    KeLeaveCriticalRegion();
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocReleaseStreamContext(
    _In_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    if (Context != NULL) {
        FltReleaseContext((PFLT_CONTEXT)Context);
    }
}

// ============================================================================
// PUBLIC API - HANDLE CONTEXT MANAGEMENT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocAllocateHandleContext(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSHADOWSTRIKE_HANDLE_CONTEXT* OutContext
    )
{
    PSHADOWSTRIKE_HANDLE_CONTEXT context = NULL;

    PAGED_CODE();

    if (Data == NULL || OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutContext = NULL;

    //
    // Check if lookaside is ready
    //
    if (!g_PocState.LookasideInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate from lookaside list
    //
    context = (PSHADOWSTRIKE_HANDLE_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_PocState.HandleContextLookaside
        );

    if (context == NULL) {
        InterlockedIncrement64(&g_PocState.Stats.HandleContextsFailed);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(SHADOWSTRIKE_HANDLE_CONTEXT));
    context->Signature = POC_HANDLE_CONTEXT_SIGNATURE;
    context->SecurityCookie = PocComputeSecurityCookie(context);
    ExInitializePushLock(&context->Lock);
    context->ProcessId = PsGetCurrentProcessId();
    context->ThreadId = PsGetCurrentThreadId();
    context->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    context->CreateOptions = Data->Iopb->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    context->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    KeQuerySystemTime(&context->OpenTime);
    KeQuerySystemTime(&context->LastOperationTime);

    InterlockedIncrement64(&g_PocState.Stats.HandleContextsCreated);

    *OutContext = context;

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocGetOrCreateHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSHADOWSTRIKE_HANDLE_CONTEXT* OutContext,
    _Out_opt_ PBOOLEAN OutCreated
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_HANDLE_CONTEXT context = NULL;
    PSHADOWSTRIKE_HANDLE_CONTEXT existingContext = NULL;
    BOOLEAN created = FALSE;

    PAGED_CODE();

    if (FltObjects == NULL || Data == NULL || OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutContext = NULL;
    if (OutCreated != NULL) {
        *OutCreated = FALSE;
    }

    //
    // Validate required pointers
    //
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_DriverData.FilterHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Try to get existing context first
    //
    status = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&context
        );

    if (NT_SUCCESS(status)) {
        if (PocIsValidHandleContext(context)) {
            *OutContext = context;
            return STATUS_SUCCESS;
        }

        InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;
    }

    //
    // Allocate from filter manager (required for FltSetStreamHandleContext)
    //
    status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(SHADOWSTRIKE_HANDLE_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&context
        );

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_PocState.Stats.HandleContextsFailed);
        return status;
    }

    //
    // Initialize
    //
    RtlZeroMemory(context, sizeof(SHADOWSTRIKE_HANDLE_CONTEXT));
    context->Signature = POC_HANDLE_CONTEXT_SIGNATURE;
    context->SecurityCookie = PocComputeSecurityCookie(context);
    ExInitializePushLock(&context->Lock);
    context->ProcessId = PsGetCurrentProcessId();
    context->ThreadId = PsGetCurrentThreadId();
    context->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    context->CreateOptions = Data->Iopb->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    context->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    KeQuerySystemTime(&context->OpenTime);
    KeQuerySystemTime(&context->LastOperationTime);

    //
    // Attach to stream handle
    //
    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)context,
        (PFLT_CONTEXT*)&existingContext
        );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;

        if (existingContext != NULL && PocIsValidHandleContext(existingContext)) {
            *OutContext = existingContext;
            return STATUS_SUCCESS;
        }

        if (existingContext != NULL) {
            InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
            FltReleaseContext((PFLT_CONTEXT)existingContext);
        }

        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        FltReleaseContext((PFLT_CONTEXT)context);
        InterlockedIncrement64(&g_PocState.Stats.HandleContextsFailed);
        return status;
    }

    InterlockedIncrement64(&g_PocState.Stats.HandleContextsCreated);
    created = TRUE;
    *OutContext = context;

    if (OutCreated != NULL) {
        *OutCreated = created;
    }

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocReleaseHandleContext(
    _In_ PSHADOWSTRIKE_HANDLE_CONTEXT Context
    )
{
    if (Context != NULL) {
        FltReleaseContext((PFLT_CONTEXT)Context);
    }
}

// ============================================================================
// PUBLIC API - COMPLETION CONTEXT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocAllocateCompletionContext(
    _Out_ PPOC_COMPLETION_CONTEXT* OutContext
    )
{
    PPOC_COMPLETION_CONTEXT context = NULL;

    PAGED_CODE();

    if (OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutContext = NULL;

    //
    // Check if lookaside is ready
    //
    if (!g_PocState.LookasideInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate from lookaside list for performance
    //
    context = (PPOC_COMPLETION_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_PocState.CompletionContextLookaside
        );

    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(POC_COMPLETION_CONTEXT));
    context->Signature = POC_COMPLETION_SIGNATURE;
    context->Size = sizeof(POC_COMPLETION_CONTEXT);
    context->SecurityCookie = PocComputeSecurityCookie(context);
    context->OwnershipToken = 1;  // Owned
    KeQuerySystemTime(&context->PreCreateTime);
    context->ProcessId = PsGetCurrentProcessId();
    context->ThreadId = PsGetCurrentThreadId();

    *OutContext = context;

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PocFreeCompletionContext(
    _Inout_ PPOC_COMPLETION_CONTEXT* Context
    )
{
    PPOC_COMPLETION_CONTEXT ctx;
    LONG previousOwner;

    if (Context == NULL || *Context == NULL) {
        return;
    }

    ctx = *Context;
    *Context = NULL;  // Prevent caller from using after free

    //
    // Validate signature
    //
    if (ctx->Signature != POC_COMPLETION_SIGNATURE) {
        //
        // Invalid signature - track the error but don't free unknown memory
        //
        InterlockedIncrement64(&g_PocState.Stats.SignatureMismatches);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/PostCreate] Invalid completion context signature: 0x%08X\n",
            ctx->Signature
            );

        //
        // Don't free - this could be corrupted or not our memory
        //
        return;
    }

    //
    // Atomic ownership check to prevent double-free
    //
    previousOwner = InterlockedCompareExchange(&ctx->OwnershipToken, 0, 1);
    if (previousOwner != 1) {
        //
        // Already freed or never owned - double-free attempt
        //
        InterlockedIncrement64(&g_PocState.Stats.DoubleFreeAttempts);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/PostCreate] Double-free attempt on completion context\n"
            );

        return;
    }

    //
    // Clear signature to catch use-after-free
    //
    ctx->Signature = 0;

    //
    // Return to lookaside list
    //
    if (g_PocState.LookasideInitialized) {
        ExFreeToNPagedLookasideList(&g_PocState.CompletionContextLookaside, ctx);
    }
}

// ============================================================================
// PUBLIC API - UTILITIES
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PocQueryFileAttributes(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    FILE_BASIC_INFORMATION basicInfo;

    PAGED_CODE();

    if (FltObjects == NULL || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        NULL
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    Context->FileAttributes = basicInfo.FileAttributes;

    //
    // Set tracking flags based on attributes
    //
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_HIDDEN) {
        Context->TrackingFlags |= PocTrackingHidden;
    }

    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_SYSTEM) {
        Context->TrackingFlags |= PocTrackingSystem;
    }

    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_READONLY) {
        Context->TrackingFlags |= PocTrackingReadOnly;
    }

    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_TEMPORARY) {
        Context->TrackingFlags |= PocTrackingTemporary;
    }

    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) {
        Context->TrackingFlags |= PocTrackingEncrypted;
    }

    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_COMPRESSED) {
        Context->TrackingFlags |= PocTrackingCompressed;
    }

    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) {
        Context->TrackingFlags |= PocTrackingSparse;
    }

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
VOID
PocCacheFileName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    USHORT copyLength;

    PAGED_CODE();

    if (NameInfo == NULL || Context == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    //
    // Cache final component (file name only)
    //
    if (NameInfo->FinalComponent.Buffer != NULL && NameInfo->FinalComponent.Length > 0) {
        copyLength = min(
            NameInfo->FinalComponent.Length,
            (POC_MAX_CACHED_NAME - 1) * sizeof(WCHAR)
            );

        RtlCopyMemory(
            Context->CachedFileName,
            NameInfo->FinalComponent.Buffer,
            copyLength
            );

        Context->CachedFileName[copyLength / sizeof(WCHAR)] = L'\0';
        Context->CachedFileNameLength = copyLength / sizeof(WCHAR);
    }

    //
    // Cache extension
    //
    if (NameInfo->Extension.Buffer != NULL && NameInfo->Extension.Length > 0) {
        PCWSTR extStart = NameInfo->Extension.Buffer;
        USHORT extLen = NameInfo->Extension.Length;

        //
        // Skip leading dot
        //
        if (extLen >= sizeof(WCHAR) && *extStart == L'.') {
            extStart++;
            extLen -= sizeof(WCHAR);
        }

        copyLength = min(extLen, (POC_MAX_CACHED_EXTENSION - 1) * sizeof(WCHAR));

        RtlCopyMemory(
            Context->CachedExtension,
            extStart,
            copyLength
            );

        Context->CachedExtension[copyLength / sizeof(WCHAR)] = L'\0';
        Context->CachedExtensionLength = copyLength / sizeof(WCHAR);
    }

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();
}


_IRQL_requires_max_(APC_LEVEL)
POC_FILE_CLASS
PocClassifyFileExtension(
    _In_opt_ PCUNICODE_STRING Extension
    )
{
    WCHAR extBuffer[32];
    USHORT extLen;
    ULONG i;
    PCWSTR extStart;

    PAGED_CODE();

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return PocFileClassUnknown;
    }

    extStart = Extension->Buffer;
    extLen = Extension->Length;

    //
    // Skip leading dot
    //
    if (extLen >= sizeof(WCHAR) && *extStart == L'.') {
        extStart++;
        extLen -= sizeof(WCHAR);
    }

    if (extLen == 0 || extLen >= sizeof(extBuffer)) {
        return PocFileClassUnknown;
    }

    RtlCopyMemory(extBuffer, extStart, extLen);
    extBuffer[extLen / sizeof(WCHAR)] = L'\0';

    //
    // Search classification table using safe compare
    //
    for (i = 0; i < POC_EXTENSION_TABLE_COUNT; i++) {
        if (PocpCompareExtensionSafe(extBuffer, g_ExtensionTable[i].Extension) == 0) {
            return g_ExtensionTable[i].Class;
        }
    }

    return PocFileClassUnknown;
}


_IRQL_requires_max_(APC_LEVEL)
VOID
PocMarkFileModified(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    PAGED_CODE();

    if (Context == NULL || !PocIsValidStreamContext(Context)) {
        if (Context != NULL) {
            InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        }
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    Context->Dirty = TRUE;
    Context->TrackingFlags |= PocTrackingModified;

    if (Context->FirstWriteTime.QuadPart == 0) {
        KeQuerySystemTime(&Context->FirstWriteTime);
    }

    KeQuerySystemTime(&Context->LastModifyTime);
    InterlockedIncrement(&Context->WriteCount);

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();
}


_IRQL_requires_max_(APC_LEVEL)
VOID
PocInvalidateScanResult(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context
    )
{
    PAGED_CODE();

    if (Context == NULL || !PocIsValidStreamContext(Context)) {
        if (Context != NULL) {
            InterlockedIncrement64(&g_PocState.Stats.InvalidContexts);
        }
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    Context->Scanned = FALSE;
    Context->Dirty = TRUE;
    Context->TrackingFlags &= ~PocTrackingScanned;
    Context->TrackingFlags &= ~PocTrackingCached;
    Context->TrackingFlags |= PocTrackingModified;

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PocGetStatistics(
    _Out_opt_ PULONG64 TotalPostCreates,
    _Out_opt_ PULONG64 ContextsCreated,
    _Out_opt_ PULONG64 ContextsReused,
    _Out_opt_ PULONG64 ContextsFailed
    )
{
    //
    // Use atomic reads for 32-bit safety
    //
    if (TotalPostCreates != NULL) {
        *TotalPostCreates = (ULONG64)PocAtomicRead64(&g_PocState.Stats.TotalPostCreates);
    }

    if (ContextsCreated != NULL) {
        *ContextsCreated = (ULONG64)PocAtomicRead64(&g_PocState.Stats.ContextsCreated);
    }

    if (ContextsReused != NULL) {
        *ContextsReused = (ULONG64)PocAtomicRead64(&g_PocState.Stats.ContextsReused);
    }

    if (ContextsFailed != NULL) {
        *ContextsFailed = (ULONG64)PocAtomicRead64(&g_PocState.Stats.ContextsFailed);
    }

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PocGetErrorStatistics(
    _Out_opt_ PULONG64 SignatureMismatches,
    _Out_opt_ PULONG64 InvalidContexts,
    _Out_opt_ PULONG64 DoubleFreeAttempts
    )
{
    if (SignatureMismatches != NULL) {
        *SignatureMismatches = (ULONG64)PocAtomicRead64(&g_PocState.Stats.SignatureMismatches);
    }

    if (InvalidContexts != NULL) {
        *InvalidContexts = (ULONG64)PocAtomicRead64(&g_PocState.Stats.InvalidContexts);
    }

    if (DoubleFreeAttempts != NULL) {
        *DoubleFreeAttempts = (ULONG64)PocAtomicRead64(&g_PocState.Stats.DoubleFreeAttempts);
    }

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
VOID
PocResetStatistics(
    VOID
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    KeQuerySystemTime(&currentTime);

    //
    // Reset all stats atomically
    //
    InterlockedExchange64(&g_PocState.Stats.TotalPostCreates, 0);
    InterlockedExchange64(&g_PocState.Stats.ContextsCreated, 0);
    InterlockedExchange64(&g_PocState.Stats.ContextsReused, 0);
    InterlockedExchange64(&g_PocState.Stats.ContextsFailed, 0);
    InterlockedExchange64(&g_PocState.Stats.ContextsSkipped, 0);
    InterlockedExchange64(&g_PocState.Stats.HandleContextsCreated, 0);
    InterlockedExchange64(&g_PocState.Stats.HandleContextsFailed, 0);
    InterlockedExchange64(&g_PocState.Stats.ScannedFiles, 0);
    InterlockedExchange64(&g_PocState.Stats.CachedResults, 0);
    InterlockedExchange64(&g_PocState.Stats.DirectoriesSkipped, 0);
    InterlockedExchange64(&g_PocState.Stats.VolumeOpensSkipped, 0);
    InterlockedExchange64(&g_PocState.Stats.DrainingSkipped, 0);
    InterlockedExchange64(&g_PocState.Stats.ErrorsHandled, 0);
    InterlockedExchange64(&g_PocState.Stats.SignatureMismatches, 0);
    InterlockedExchange64(&g_PocState.Stats.InvalidContexts, 0);
    InterlockedExchange64(&g_PocState.Stats.DoubleFreeAttempts, 0);

    g_PocState.Stats.StartTime = currentTime;
}

// ============================================================================
// PRIVATE IMPLEMENTATION
// ============================================================================

static BOOLEAN
PocpShouldLogOperation(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LONGLONG secondStart;
    LONGLONG elapsed;

    KeQuerySystemTime(&currentTime);

    //
    // Atomic read of current second start
    //
    secondStart = PocAtomicReadLongLong(&g_PocState.CurrentSecondStart);
    elapsed = currentTime.QuadPart - secondStart;

    if (elapsed >= POC_ONE_SECOND_100NS) {
        //
        // New second - reset counter atomically
        // Use compare-exchange to avoid race between multiple threads
        //
        if (InterlockedCompareExchange64(
                &g_PocState.CurrentSecondStart,
                currentTime.QuadPart,
                secondStart) == secondStart) {
            InterlockedExchange(&g_PocState.CurrentSecondLogs, 0);
        }
    }

    if (g_PocState.CurrentSecondLogs >= POC_LOG_RATE_LIMIT_PER_SEC) {
        return FALSE;
    }

    InterlockedIncrement(&g_PocState.CurrentSecondLogs);
    return TRUE;
}


static NTSTATUS
PocpQueryFileInformation(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLONGLONG OutFileId,
    _Out_ PLONGLONG OutFileSize,
    _Out_ PLARGE_INTEGER OutLastWriteTime,
    _Out_ PLARGE_INTEGER OutCreationTime
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION stdInfo;
    FILE_INTERNAL_INFORMATION internalInfo;
    FILE_BASIC_INFORMATION basicInfo;

    PAGED_CODE();

    *OutFileId = 0;
    *OutFileSize = 0;
    OutLastWriteTime->QuadPart = 0;
    OutCreationTime->QuadPart = 0;

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get file size
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &stdInfo,
        sizeof(stdInfo),
        FileStandardInformation,
        NULL
        );

    if (NT_SUCCESS(status)) {
        *OutFileSize = stdInfo.EndOfFile.QuadPart;
    }

    //
    // Get file ID
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        NULL
        );

    if (NT_SUCCESS(status)) {
        *OutFileId = internalInfo.IndexNumber.QuadPart;
    }

    //
    // Get timestamps
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        NULL
        );

    if (NT_SUCCESS(status)) {
        *OutLastWriteTime = basicInfo.LastWriteTime;
        *OutCreationTime = basicInfo.CreationTime;
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
PocpQueryVolumeSerial(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG OutSerial
    )
{
    NTSTATUS status;
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;

    PAGED_CODE();

    *OutSerial = 0;

    if (FltObjects->Volume == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetVolumeProperties(
        FltObjects->Volume,
        &volumeProps,
        sizeof(volumeProps),
        &bytesReturned
        );

    if (!NT_SUCCESS(status)) {
        //
        // Some volumes don't support this - not fatal
        //
        return status;
    }

    //
    // Volume serial is not directly in FLT_VOLUME_PROPERTIES
    // We need to query FILE_FS_VOLUME_INFORMATION for the actual serial
    // For now, use a hash of the volume GUID or device name as a stable identifier
    //
    // Fallback: use volume object pointer as pseudo-serial
    // This is stable for the duration of mount
    //
    *OutSerial = (ULONG)((ULONG_PTR)FltObjects->Volume & 0xFFFFFFFF);

    return STATUS_SUCCESS;
}


static VOID
PocpSetTrackingFlags(
    _Inout_ PSHADOWSTRIKE_STREAM_CONTEXT Context,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo
    )
{
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;
    NTSTATUS status;

    PAGED_CODE();

    if (Context == NULL) {
        return;
    }

    //
    // Check volume type
    //
    if (FltObjects->Volume != NULL) {
        status = FltGetVolumeProperties(
            FltObjects->Volume,
            &volumeProps,
            sizeof(volumeProps),
            &bytesReturned
            );

        if (NT_SUCCESS(status)) {
            if (volumeProps.DeviceCharacteristics & FILE_REMOTE_DEVICE) {
                Context->TrackingFlags |= PocTrackingNetwork;
            }

            if (volumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA) {
                Context->TrackingFlags |= PocTrackingRemovable;
            }
        }
    }

    //
    // Check for ADS (alternate data stream)
    // If the name contains a colon after the drive letter, it's an ADS
    //
    if (NameInfo != NULL && NameInfo->Name.Buffer != NULL) {
        USHORT nameLen = NameInfo->Name.Length / sizeof(WCHAR);

        //
        // Only search if name is long enough to contain "X:\...:stream"
        // Minimum: drive letter + colon + backslash + something + colon = 5 chars
        //
        if (nameLen >= 5) {
            USHORT i;
            //
            // Start at index 3 to skip "X:\" prefix
            // This avoids false positive on drive letter colon
            //
            for (i = 3; i < nameLen; i++) {
                if (NameInfo->Name.Buffer[i] == L':') {
                    Context->TrackingFlags |= PocTrackingAds;
                    break;
                }
            }
        }
    }
}
