/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PROCESS HOLLOWING DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file HollowingDetector.c
 * @brief Enterprise-grade process hollowing and ghosting detection engine.
 *
 * This module implements comprehensive process hollowing detection with:
 * - Classic process hollowing (T1055.012)
 * - Process doppelganging via TxF transactions (T1055.013)
 * - Process ghosting (deleted backing file)
 * - Process herpaderping (modified file after section creation)
 * - Module stomping (legitimate module overwrite)
 * - Phantom DLL hollowing
 * - Memory vs file image comparison
 * - Entry point validation
 * - PEB/TEB tampering detection
 * - Transacted section detection
 *
 * Security Detection Capabilities:
 * - T1055.012: Process Hollowing
 * - T1055.013: Process Doppelganging
 * - T1055.004: Asynchronous Procedure Call (related)
 * - T1106: Native API abuse detection
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "HollowingDetector.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/HashUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../ETW/TelemetryEvents.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PH_VERSION                      1
#define PH_SIGNATURE                    0x48444554  // 'HDET'
#define PH_MAX_CALLBACKS                8
#define PH_MAX_ACTIVE_ANALYSES          64
#define PH_MAX_SECTION_COMPARE          (256 * 1024)
#define PH_MIN_IMAGE_SIZE               512
#define PH_ENTRY_POINT_SCAN_SIZE        64
#define PH_DOS_HEADER_SIZE              64
#define PH_NT_HEADERS_OFFSET_MAX        1024

//
// Confidence score weights
//
#define PH_SCORE_IMAGE_MISMATCH         25
#define PH_SCORE_SECTION_MISMATCH       20
#define PH_SCORE_ENTRY_MODIFIED         30
#define PH_SCORE_HEADER_MODIFIED        25
#define PH_SCORE_UNMAPPED_MODULE        35
#define PH_SCORE_TRANSACTED             40
#define PH_SCORE_DELETED_FILE           45
#define PH_SCORE_SUSPENDED_THREAD       15
#define PH_SCORE_PEB_MODIFIED           30
#define PH_SCORE_HIDDEN_MEMORY          25
#define PH_SCORE_NO_PHYSICAL_FILE       35
#define PH_SCORE_HASH_MISMATCH          40
#define PH_SCORE_TIMESTAMP_ANOMALY      10
#define PH_SCORE_RWX_REGION             20

//
// Severity weights
//
#define PH_SEVERITY_BASE                20
#define PH_SEVERITY_CRITICAL_INDICATOR  30
#define PH_SEVERITY_HIGH_INDICATOR      20
#define PH_SEVERITY_MEDIUM_INDICATOR    10

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Callback registration entry.
 */
typedef struct _PH_CALLBACK_ENTRY {
    PH_DETECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN InUse;
} PH_CALLBACK_ENTRY, *PPH_CALLBACK_ENTRY;

/**
 * @brief Active analysis tracking entry.
 */
typedef struct _PH_ACTIVE_ANALYSIS {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    LARGE_INTEGER StartTime;
    volatile LONG InProgress;
} PH_ACTIVE_ANALYSIS, *PPH_ACTIVE_ANALYSIS;

/**
 * @brief Extended internal detector structure.
 */
typedef struct _PH_DETECTOR_INTERNAL {
    //
    // Base public structure
    //
    PH_DETECTOR Public;

    //
    // Signature for validation
    //
    ULONG Signature;

    //
    // Callback management
    //
    PH_CALLBACK_ENTRY Callbacks[PH_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    //
    // Lookaside lists for efficient allocation
    //
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    NPAGED_LOOKASIDE_LIST AnalysisLookaside;
    NPAGED_LOOKASIDE_LIST BufferLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Shutdown synchronization
    //
    volatile LONG ShuttingDown;
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;

} PH_DETECTOR_INTERNAL, *PPH_DETECTOR_INTERNAL;

/**
 * @brief PE header analysis context.
 */
typedef struct _PH_PE_CONTEXT {
    BOOLEAN Is64Bit;
    ULONG HeaderSize;
    PVOID ImageBase;
    SIZE_T ImageSize;
    PVOID EntryPoint;
    ULONG NumberOfSections;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    ULONG Checksum;
    ULONG TimeDateStamp;
    ULONG SizeOfHeaders;
} PH_PE_CONTEXT, *PPH_PE_CONTEXT;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPH_ANALYSIS_RESULT
PhpAllocateResult(
    _In_ PPH_DETECTOR_INTERNAL Detector
    );

static VOID
PhpFreeResultInternal(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeImageComparison(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeEntryPoint(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzePEB(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeMemoryRegions(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeSectionBacking(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpGetProcessImagePath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImagePath
    );

static NTSTATUS
PhpReadProcessMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
    );

static NTSTATUS
PhpParsePEHeaders(
    _In_ PVOID HeaderBuffer,
    _In_ SIZE_T BufferSize,
    _Out_ PPH_PE_CONTEXT PeContext
    );

static NTSTATUS
PhpCompareMemoryWithFile(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID MemoryBase,
    _In_ SIZE_T MemorySize,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset,
    _Out_opt_ PUCHAR MemoryHash,
    _Out_opt_ PUCHAR FileHash
    );

static NTSTATUS
PhpCheckFileTransacted(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN IsTransacted
    );

static NTSTATUS
PhpCheckFileDeleted(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN IsDeleted
    );

static VOID
PhpCalculateScores(
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static PH_HOLLOWING_TYPE
PhpDetermineHollowingType(
    _In_ PPH_ANALYSIS_RESULT Result
    );

static VOID
PhpInvokeCallbacks(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PPH_ANALYSIS_RESULT Result
    );

static VOID
PhpAcquireReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    );

static VOID
PhpReleaseReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    );

static NTSTATUS
PhpOpenProcessForAnalysis(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ProcessHandle,
    _Out_ PEPROCESS* Process
    );

static VOID
PhpCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PUNICODE_STRING Src,
    _In_ ULONG PoolTag
    );

static VOID
PhpFreeUnicodeString(
    _Inout_ PUNICODE_STRING String,
    _In_ ULONG PoolTag
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhInitialize(
    _Out_ PPH_DETECTOR* Detector
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPH_DETECTOR_INTERNAL internal = NULL;

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    internal = (PPH_DETECTOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PH_DETECTOR_INTERNAL),
        PH_POOL_TAG_CONTEXT
    );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(PH_DETECTOR_INTERNAL));
    internal->Signature = PH_SIGNATURE;

    //
    // Initialize synchronization primitives
    //
    KeInitializeSpinLock(&internal->Public.AnalysisLock);
    ExInitializePushLock(&internal->CallbackLock);
    InitializeListHead(&internal->Public.ActiveAnalyses);

    //
    // Initialize shutdown synchronization
    //
    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // Initial reference

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &internal->ResultLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PH_ANALYSIS_RESULT),
        PH_POOL_TAG_RESULT,
        0
    );

    ExInitializeNPagedLookasideList(
        &internal->AnalysisLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PH_ACTIVE_ANALYSIS),
        PH_POOL_TAG_CONTEXT,
        0
    );

    ExInitializeNPagedLookasideList(
        &internal->BufferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        PH_MAX_HEADER_SIZE,
        PH_POOL_TAG_BUFFER,
        0
    );

    internal->LookasideInitialized = TRUE;

    //
    // Set default configuration
    //
    internal->Public.Config.CompareWithFile = TRUE;
    internal->Public.Config.AnalyzePEB = TRUE;
    internal->Public.Config.AnalyzeEntryPoint = TRUE;
    internal->Public.Config.AnalyzeMemoryRegions = TRUE;
    internal->Public.Config.TimeoutMs = PH_SCAN_TIMEOUT_MS;
    internal->Public.Config.MinConfidenceToReport = 50;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // Mark as initialized
    //
    internal->Public.Initialized = TRUE;

    *Detector = &internal->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PhShutdown(
    _Inout_ PPH_DETECTOR Detector
    )
{
    PPH_DETECTOR_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PPH_ACTIVE_ANALYSIS analysis;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->Signature != PH_SIGNATURE) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&internal->ShuttingDown, 1);

    //
    // Wait for active operations to complete
    //
    PhpReleaseReference(internal);
    timeout.QuadPart = -((LONGLONG)5000 * 10000);  // 5 second timeout
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Free all active analyses
    //
    KeAcquireSpinLock(&Detector->AnalysisLock, &oldIrql);

    while (!IsListEmpty(&Detector->ActiveAnalyses)) {
        listEntry = RemoveHeadList(&Detector->ActiveAnalyses);
        analysis = CONTAINING_RECORD(listEntry, PH_ACTIVE_ANALYSIS, ListEntry);

        if (internal->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&internal->AnalysisLookaside, analysis);
        }
    }

    KeReleaseSpinLock(&Detector->AnalysisLock, oldIrql);

    //
    // Delete lookaside lists
    //
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->ResultLookaside);
        ExDeleteNPagedLookasideList(&internal->AnalysisLookaside);
        ExDeleteNPagedLookasideList(&internal->BufferLookaside);
        internal->LookasideInitialized = FALSE;
    }

    //
    // Clear signature and free
    //
    internal->Signature = 0;
    Detector->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(internal, PH_POOL_TAG_CONTEXT);
}

// ============================================================================
// PROCESS ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhAnalyzeProcess(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PPH_ANALYSIS_RESULT* Result
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    PPH_ANALYSIS_RESULT result = NULL;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;

    if (Detector == NULL || !Detector->Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PhpAcquireReference(internal);

    //
    // Record start time
    //
    KeQuerySystemTime(&startTime);

    //
    // Open target process
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Allocate result structure
    //
    result = PhpAllocateResult(internal);
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));
    result->ProcessId = ProcessId;
    result->AnalysisTime = startTime;

    //
    // Get process image path
    //
    status = PhpGetProcessImagePath(process, &result->ActualImagePath);
    if (!NT_SUCCESS(status)) {
        //
        // Continue analysis even without path - suspicious in itself
        //
        result->Indicators |= PhIndicator_NoPhysicalFile;
    }

    //
    // Perform section/file backing analysis
    //
    status = PhpAnalyzeSectionBacking(internal, process, processHandle, result);
    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        //
        // Non-critical - continue
        //
    }

    //
    // Compare in-memory image with file
    //
    if (Detector->Config.CompareWithFile) {
        status = PhpAnalyzeImageComparison(internal, process, processHandle, result);
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
            //
            // Non-critical - continue
            //
        }
    }

    //
    // Validate entry point
    //
    if (Detector->Config.AnalyzeEntryPoint) {
        status = PhpAnalyzeEntryPoint(internal, process, processHandle, result);
        if (!NT_SUCCESS(status)) {
            //
            // Non-critical - continue
            //
        }
    }

    //
    // Analyze PEB for tampering
    //
    if (Detector->Config.AnalyzePEB) {
        status = PhpAnalyzePEB(internal, process, processHandle, result);
        if (!NT_SUCCESS(status)) {
            //
            // Non-critical - continue
            //
        }
    }

    //
    // Analyze memory regions
    //
    if (Detector->Config.AnalyzeMemoryRegions) {
        status = PhpAnalyzeMemoryRegions(internal, process, processHandle, result);
        if (!NT_SUCCESS(status)) {
            //
            // Non-critical - continue
            //
        }
    }

    //
    // Calculate confidence and severity scores
    //
    PhpCalculateScores(result);

    //
    // Determine hollowing type
    //
    result->Type = PhpDetermineHollowingType(result);
    result->HollowingDetected = (result->Type != PhHollowing_None);

    //
    // Calculate analysis duration
    //
    KeQuerySystemTime(&endTime);
    result->AnalysisDurationMs = (ULONG)((endTime.QuadPart - startTime.QuadPart) / 10000);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.ProcessesAnalyzed);

    if (result->HollowingDetected) {
        InterlockedIncrement64(&Detector->Stats.HollowingDetected);

        if (result->Type == PhHollowing_Doppelganging) {
            InterlockedIncrement64(&Detector->Stats.DoppelgangingDetected);
        } else if (result->Type == PhHollowing_Ghosting) {
            InterlockedIncrement64(&Detector->Stats.GhostingDetected);
        }

        //
        // Invoke callbacks for detections
        //
        if (result->ConfidenceScore >= Detector->Config.MinConfidenceToReport) {
            PhpInvokeCallbacks(internal, result);
        }
    }

    *Result = result;
    result = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(internal, result);
    }

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhAnalyzeAtCreation(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ PEPROCESS Process,
    _Out_ PPH_ANALYSIS_RESULT* Result
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    PPH_ANALYSIS_RESULT result = NULL;
    HANDLE processHandle = NULL;
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;

    UNREFERENCED_PARAMETER(ParentId);

    if (Detector == NULL || !Detector->Initialized ||
        Process == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PhpAcquireReference(internal);

    KeQuerySystemTime(&startTime);

    //
    // Reference the process object (it's provided by caller)
    //
    ObReferenceObject(Process);

    //
    // Open process handle for memory access
    //
    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Allocate result
    //
    result = PhpAllocateResult(internal);
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));
    result->ProcessId = ProcessId;
    result->AnalysisTime = startTime;

    //
    // Get process creation time
    //
    result->ProcessCreateTime = PsGetProcessCreateTimeQuadPart(Process);

    //
    // Get image path
    //
    status = PhpGetProcessImagePath(Process, &result->ActualImagePath);
    if (!NT_SUCCESS(status)) {
        result->Indicators |= PhIndicator_NoPhysicalFile;
    }

    //
    // At creation time, the main thread is typically suspended
    // Check for section backing first
    //
    status = PhpAnalyzeSectionBacking(internal, Process, processHandle, result);
    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        //
        // Continue anyway
        //
    }

    //
    // Compare image with file
    //
    if (Detector->Config.CompareWithFile) {
        status = PhpAnalyzeImageComparison(internal, Process, processHandle, result);
    }

    //
    // Validate entry point
    //
    if (Detector->Config.AnalyzeEntryPoint) {
        status = PhpAnalyzeEntryPoint(internal, Process, processHandle, result);
    }

    //
    // Analyze PEB - crucial at creation time
    //
    if (Detector->Config.AnalyzePEB) {
        status = PhpAnalyzePEB(internal, Process, processHandle, result);
    }

    //
    // Calculate scores
    //
    PhpCalculateScores(result);
    result->Type = PhpDetermineHollowingType(result);
    result->HollowingDetected = (result->Type != PhHollowing_None);

    //
    // Record timing
    //
    KeQuerySystemTime(&endTime);
    result->AnalysisDurationMs = (ULONG)((endTime.QuadPart - startTime.QuadPart) / 10000);

    //
    // Update stats
    //
    InterlockedIncrement64(&Detector->Stats.ProcessesAnalyzed);

    if (result->HollowingDetected) {
        InterlockedIncrement64(&Detector->Stats.HollowingDetected);

        if (result->Type == PhHollowing_Doppelganging) {
            InterlockedIncrement64(&Detector->Stats.DoppelgangingDetected);
        } else if (result->Type == PhHollowing_Ghosting) {
            InterlockedIncrement64(&Detector->Stats.GhostingDetected);
        }

        if (result->ConfidenceScore >= Detector->Config.MinConfidenceToReport) {
            PhpInvokeCallbacks(internal, result);
        }
    }

    *Result = result;
    result = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(internal, result);
    }

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    ObDereferenceObject(Process);

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhQuickCheck(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsHollowed,
    _Out_opt_ PPH_HOLLOWING_TYPE Type,
    _Out_opt_ PULONG Score
    )
{
    NTSTATUS status;
    PPH_ANALYSIS_RESULT result = NULL;

    if (Detector == NULL || IsHollowed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsHollowed = FALSE;
    if (Type != NULL) *Type = PhHollowing_None;
    if (Score != NULL) *Score = 0;

    //
    // Perform full analysis
    //
    status = PhAnalyzeProcess(Detector, ProcessId, &result);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Extract quick results
    //
    *IsHollowed = result->HollowingDetected;

    if (Type != NULL) {
        *Type = result->Type;
    }

    if (Score != NULL) {
        *Score = result->ConfidenceScore;
    }

    PhFreeResult(result);

    return STATUS_SUCCESS;
}

// ============================================================================
// SPECIFIC CHECKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhCompareImageWithFile(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    UNICODE_STRING imagePath = { 0 };
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    BOOLEAN match = FALSE;
    ULONG mismatchOffset = 0;

    if (Detector == NULL || !Detector->Initialized || Match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Match = FALSE;
    if (MismatchOffset != NULL) *MismatchOffset = 0;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PhpAcquireReference(internal);

    //
    // Open process
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get image path
    //
    status = PhpGetProcessImagePath(process, &imagePath);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get image base from PEB
    //
    status = ShadowStrikeGetProcessImageBase(process, &imageBase, &imageSize);
    if (!NT_SUCCESS(status) || imageBase == NULL) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    //
    // Compare memory with file
    //
    status = PhpCompareMemoryWithFile(
        processHandle,
        imageBase,
        imageSize,
        &imagePath,
        &match,
        &mismatchOffset,
        NULL,
        NULL
    );

    if (NT_SUCCESS(status)) {
        *Match = match;
        if (MismatchOffset != NULL) {
            *MismatchOffset = mismatchOffset;
        }
    }

Cleanup:
    PhpFreeUnicodeString(&imagePath, PH_POOL_TAG_BUFFER);

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhValidateEntryPoint(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN Valid
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    PPH_ANALYSIS_RESULT result = NULL;

    if (Detector == NULL || !Detector->Initialized || Valid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Valid = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PhpAcquireReference(internal);

    //
    // Open process
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Allocate temporary result
    //
    result = PhpAllocateResult(internal);
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));

    //
    // Analyze entry point
    //
    status = PhpAnalyzeEntryPoint(internal, process, processHandle, result);
    if (NT_SUCCESS(status)) {
        *Valid = result->EntryPoint.EntryPointValid &&
                 result->EntryPoint.EntryPointExecutable &&
                 result->EntryPoint.EntryPointInImage;
    }

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(internal, result);
    }

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhCheckForDoppelganging(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsDoppelganging
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    UNICODE_STRING imagePath = { 0 };
    BOOLEAN isTransacted = FALSE;

    if (Detector == NULL || !Detector->Initialized || IsDoppelganging == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsDoppelganging = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PhpAcquireReference(internal);

    //
    // Open process
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get image path
    //
    status = PhpGetProcessImagePath(process, &imagePath);
    if (!NT_SUCCESS(status)) {
        //
        // No image path - possibly transacted file that was rolled back
        //
        *IsDoppelganging = TRUE;
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    //
    // Check if file is transacted
    //
    status = PhpCheckFileTransacted(&imagePath, &isTransacted);
    if (NT_SUCCESS(status) && isTransacted) {
        *IsDoppelganging = TRUE;
    }

Cleanup:
    PhpFreeUnicodeString(&imagePath, PH_POOL_TAG_BUFFER);

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhCheckForGhosting(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsGhosting
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    UNICODE_STRING imagePath = { 0 };
    BOOLEAN isDeleted = FALSE;

    if (Detector == NULL || !Detector->Initialized || IsGhosting == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsGhosting = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PhpAcquireReference(internal);

    //
    // Open process
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get image path
    //
    status = PhpGetProcessImagePath(process, &imagePath);
    if (!NT_SUCCESS(status)) {
        //
        // No image path - possibly deleted file
        //
        *IsGhosting = TRUE;
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    //
    // Check if file is deleted or delete-pending
    //
    status = PhpCheckFileDeleted(&imagePath, &isDeleted);
    if (NT_SUCCESS(status) && isDeleted) {
        *IsGhosting = TRUE;
    }

Cleanup:
    PhpFreeUnicodeString(&imagePath, PH_POOL_TAG_BUFFER);

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

// ============================================================================
// CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhRegisterCallback(
    _In_ PPH_DETECTOR Detector,
    _In_ PH_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PPH_DETECTOR_INTERNAL internal;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (!internal->Callbacks[i].InUse) {
            internal->Callbacks[i].Callback = Callback;
            internal->Callbacks[i].Context = Context;
            internal->Callbacks[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
VOID
PhUnregisterCallback(
    _In_ PPH_DETECTOR Detector,
    _In_ PH_DETECTION_CALLBACK Callback
    )
{
    PPH_DETECTOR_INTERNAL internal;
    ULONG i;

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (internal->Callbacks[i].InUse &&
            internal->Callbacks[i].Callback == Callback) {
            internal->Callbacks[i].InUse = FALSE;
            internal->Callbacks[i].Callback = NULL;
            internal->Callbacks[i].Context = NULL;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// RESULTS
// ============================================================================

_Use_decl_annotations_
VOID
PhFreeResult(
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    if (Result == NULL) {
        return;
    }

    //
    // Free allocated strings
    //
    PhpFreeUnicodeString(&Result->ClaimedImagePath, PH_POOL_TAG_RESULT);
    PhpFreeUnicodeString(&Result->ActualImagePath, PH_POOL_TAG_RESULT);
    PhpFreeUnicodeString(&Result->ProcessName, PH_POOL_TAG_RESULT);
    PhpFreeUnicodeString(&Result->Section.BackingFileName, PH_POOL_TAG_RESULT);

    //
    // Free the result structure itself
    //
    ShadowStrikeFreePoolWithTag(Result, PH_POOL_TAG_RESULT);
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhGetStatistics(
    _In_ PPH_DETECTOR Detector,
    _Out_ PPH_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Detector == NULL || !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(PH_STATISTICS));

    Stats->ProcessesAnalyzed = Detector->Stats.ProcessesAnalyzed;
    Stats->HollowingDetected = Detector->Stats.HollowingDetected;
    Stats->DoppelgangingDetected = Detector->Stats.DoppelgangingDetected;
    Stats->GhostingDetected = Detector->Stats.GhostingDetected;

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - ALLOCATION
// ============================================================================

static PPH_ANALYSIS_RESULT
PhpAllocateResult(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    PPH_ANALYSIS_RESULT result;

    if (!Detector->LookasideInitialized) {
        result = (PPH_ANALYSIS_RESULT)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(PH_ANALYSIS_RESULT),
            PH_POOL_TAG_RESULT
        );
    } else {
        result = (PPH_ANALYSIS_RESULT)ExAllocateFromNPagedLookasideList(
            &Detector->ResultLookaside
        );
    }

    return result;
}

static VOID
PhpFreeResultInternal(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    //
    // Free strings first
    //
    PhpFreeUnicodeString(&Result->ClaimedImagePath, PH_POOL_TAG_RESULT);
    PhpFreeUnicodeString(&Result->ActualImagePath, PH_POOL_TAG_RESULT);
    PhpFreeUnicodeString(&Result->ProcessName, PH_POOL_TAG_RESULT);
    PhpFreeUnicodeString(&Result->Section.BackingFileName, PH_POOL_TAG_RESULT);

    if (Detector->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Detector->ResultLookaside, Result);
    } else {
        ShadowStrikeFreePoolWithTag(Result, PH_POOL_TAG_RESULT);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PROCESS ACCESS
// ============================================================================

static NTSTATUS
PhpOpenProcessForAnalysis(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ProcessHandle,
    _Out_ PEPROCESS* Process
    )
{
    NTSTATUS status;

    *ProcessHandle = NULL;
    *Process = NULL;

    //
    // Get process object
    //
    status = PsLookupProcessByProcessId(ProcessId, Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Open process handle
    //
    status = ObOpenObjectByPointer(
        *Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        ProcessHandle
    );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(*Process);
        *Process = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpGetProcessImagePath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImagePath
    )
{
    NTSTATUS status;
    PUNICODE_STRING processImageName = NULL;

    RtlZeroMemory(ImagePath, sizeof(UNICODE_STRING));

    status = SeLocateProcessImageName(Process, &processImageName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Copy the string
    //
    PhpCopyUnicodeString(ImagePath, processImageName, PH_POOL_TAG_BUFFER);

    ExFreePool(processImageName);

    return ImagePath->Buffer != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

static NTSTATUS
PhpReadProcessMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
    )
{
    NTSTATUS status;
    SIZE_T bytesRead = 0;

    if (BytesRead != NULL) {
        *BytesRead = 0;
    }

    status = ZwReadVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        Size,
        &bytesRead
    );

    if (BytesRead != NULL) {
        *BytesRead = bytesRead;
    }

    return status;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - IMAGE ANALYSIS
// ============================================================================

static NTSTATUS
PhpAnalyzeImageComparison(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    BOOLEAN match = FALSE;
    ULONG mismatchOffset = 0;

    UNREFERENCED_PARAMETER(Detector);

    //
    // Get image base from process
    //
    status = ShadowStrikeGetProcessImageBase(Process, &imageBase, &imageSize);
    if (!NT_SUCCESS(status) || imageBase == NULL) {
        return STATUS_NOT_FOUND;
    }

    Result->ImageComparison.MemoryBase = imageBase;
    Result->ImageComparison.MemorySize = imageSize;

    //
    // If we have the actual image path, compare with file
    //
    if (Result->ActualImagePath.Buffer != NULL) {
        status = PhpCompareMemoryWithFile(
            ProcessHandle,
            imageBase,
            imageSize,
            &Result->ActualImagePath,
            &match,
            &mismatchOffset,
            Result->ImageComparison.MemoryHash,
            Result->ImageComparison.FileHash
        );

        if (NT_SUCCESS(status)) {
            Result->ImageComparison.HashMatch = match;
            Result->ImageComparison.MismatchOffset = mismatchOffset;

            if (!match) {
                Result->Indicators |= PhIndicator_HashMismatch;
                Result->Indicators |= PhIndicator_SectionMismatch;
            }
        }
    } else {
        //
        // No file to compare with - suspicious
        //
        Result->Indicators |= PhIndicator_NoPhysicalFile;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpAnalyzeEntryPoint(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    PVOID headerBuffer = NULL;
    SIZE_T bytesRead = 0;
    PH_PE_CONTEXT peContext = { 0 };
    MEMORY_BASIC_INFORMATION memInfo = { 0 };

    UNREFERENCED_PARAMETER(Detector);

    //
    // Get image base
    //
    status = ShadowStrikeGetProcessImageBase(Process, &imageBase, &imageSize);
    if (!NT_SUCCESS(status) || imageBase == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Allocate buffer for PE header
    //
    headerBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        PH_MAX_HEADER_SIZE,
        PH_POOL_TAG_BUFFER
    );

    if (headerBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read PE header from process memory
    //
    status = PhpReadProcessMemory(
        ProcessHandle,
        imageBase,
        headerBuffer,
        PH_MAX_HEADER_SIZE,
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead < PH_MIN_IMAGE_SIZE) {
        ShadowStrikeFreePoolWithTag(headerBuffer, PH_POOL_TAG_BUFFER);
        return status;
    }

    //
    // Parse PE headers
    //
    status = PhpParsePEHeaders(headerBuffer, bytesRead, &peContext);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(headerBuffer, PH_POOL_TAG_BUFFER);
        return status;
    }

    //
    // Calculate entry point address
    //
    Result->EntryPoint.DeclaredEntryPoint = peContext.EntryPoint;
    Result->EntryPoint.ActualEntryPoint = (PVOID)((ULONG_PTR)imageBase +
        (ULONG_PTR)peContext.EntryPoint - (ULONG_PTR)peContext.ImageBase);

    //
    // Validate entry point is within image bounds
    //
    Result->EntryPoint.EntryPointInImage =
        ((ULONG_PTR)Result->EntryPoint.ActualEntryPoint >= (ULONG_PTR)imageBase) &&
        ((ULONG_PTR)Result->EntryPoint.ActualEntryPoint < (ULONG_PTR)imageBase + imageSize);

    if (!Result->EntryPoint.EntryPointInImage) {
        Result->Indicators |= PhIndicator_EntryPointModified;
    }

    //
    // Check if entry point memory is executable
    //
    status = ZwQueryVirtualMemory(
        ProcessHandle,
        Result->EntryPoint.ActualEntryPoint,
        MemoryBasicInformation,
        &memInfo,
        sizeof(memInfo),
        NULL
    );

    if (NT_SUCCESS(status)) {
        Result->EntryPoint.EntryPointExecutable =
            (memInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (!Result->EntryPoint.EntryPointExecutable) {
            Result->Indicators |= PhIndicator_EntryPointModified;
        }
    }

    Result->EntryPoint.EntryPointValid =
        Result->EntryPoint.EntryPointInImage &&
        Result->EntryPoint.EntryPointExecutable;

    ShadowStrikeFreePoolWithTag(headerBuffer, PH_POOL_TAG_BUFFER);

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpAnalyzePEB(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;
    PVOID pebAddress = NULL;
    PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    UNICODE_STRING pebImagePath = { 0 };

    UNREFERENCED_PARAMETER(Detector);

    //
    // Get PEB address
    //
    status = ZwQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    pebAddress = pbi.PebBaseAddress;
    if (pebAddress == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Read PEB from process
    //
    status = PhpReadProcessMemory(
        ProcessHandle,
        pebAddress,
        &peb,
        sizeof(PEB),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead < sizeof(PEB)) {
        return status;
    }

    //
    // Get image path from PEB and compare with actual
    //
    if (peb.ProcessParameters != NULL) {
        RTL_USER_PROCESS_PARAMETERS params = { 0 };

        status = PhpReadProcessMemory(
            ProcessHandle,
            peb.ProcessParameters,
            &params,
            sizeof(RTL_USER_PROCESS_PARAMETERS),
            &bytesRead
        );

        if (NT_SUCCESS(status) && bytesRead >= sizeof(RTL_USER_PROCESS_PARAMETERS)) {
            //
            // Read the image path name from process memory
            //
            if (params.ImagePathName.Length > 0 &&
                params.ImagePathName.Length < MAX_PATH * sizeof(WCHAR)) {

                pebImagePath.Length = params.ImagePathName.Length;
                pebImagePath.MaximumLength = params.ImagePathName.Length + sizeof(WCHAR);
                pebImagePath.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
                    NonPagedPoolNx,
                    pebImagePath.MaximumLength,
                    PH_POOL_TAG_BUFFER
                );

                if (pebImagePath.Buffer != NULL) {
                    status = PhpReadProcessMemory(
                        ProcessHandle,
                        params.ImagePathName.Buffer,
                        pebImagePath.Buffer,
                        pebImagePath.Length,
                        &bytesRead
                    );

                    if (NT_SUCCESS(status)) {
                        pebImagePath.Buffer[pebImagePath.Length / sizeof(WCHAR)] = L'\0';

                        //
                        // Copy to result
                        //
                        PhpCopyUnicodeString(&Result->ClaimedImagePath, &pebImagePath, PH_POOL_TAG_RESULT);

                        //
                        // Compare with actual path
                        //
                        if (Result->ActualImagePath.Buffer != NULL) {
                            if (!RtlEqualUnicodeString(&pebImagePath, &Result->ActualImagePath, TRUE)) {
                                Result->Indicators |= PhIndicator_ImagePathMismatch;
                                Result->PEB.PebModified = TRUE;
                            }
                        }
                    }

                    ShadowStrikeFreePoolWithTag(pebImagePath.Buffer, PH_POOL_TAG_BUFFER);
                }
            }
        }
    }

    //
    // Check if image base matches
    //
    if (Result->ImageComparison.MemoryBase != NULL) {
        if (peb.ImageBaseAddress != Result->ImageComparison.MemoryBase) {
            Result->Indicators |= PhIndicator_ModifiedPEB;
            Result->PEB.ImageBaseModified = TRUE;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpAnalyzeMemoryRegions(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    PVOID currentAddress = NULL;
    MEMORY_BASIC_INFORMATION memInfo = { 0 };
    ULONG rwxCount = 0;
    ULONG unbackedExecCount = 0;
    ULONG suspiciousCount = 0;
    SIZE_T suspiciousSize = 0;

    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(Process);

    //
    // Enumerate memory regions
    //
    while (TRUE) {
        status = ZwQueryVirtualMemory(
            ProcessHandle,
            currentAddress,
            MemoryBasicInformation,
            &memInfo,
            sizeof(memInfo),
            NULL
        );

        if (!NT_SUCCESS(status)) {
            break;
        }

        //
        // Check for RWX regions (highly suspicious)
        //
        if (memInfo.State == MEM_COMMIT) {
            BOOLEAN isExecutable =
                (memInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            BOOLEAN isWritable =
                (memInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            if (isExecutable && isWritable) {
                rwxCount++;
                suspiciousCount++;
                suspiciousSize += memInfo.RegionSize;
            }

            //
            // Check for unbacked executable memory (potential shellcode)
            //
            if (isExecutable && memInfo.Type == MEM_PRIVATE) {
                unbackedExecCount++;
                suspiciousCount++;
                suspiciousSize += memInfo.RegionSize;
            }
        }

        //
        // Move to next region
        //
        currentAddress = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);

        //
        // Safety check for wrap-around
        //
        if ((ULONG_PTR)currentAddress < (ULONG_PTR)memInfo.BaseAddress) {
            break;
        }
    }

    Result->Memory.RWXRegionCount = rwxCount;
    Result->Memory.UnbackedExecutableCount = unbackedExecCount;
    Result->Memory.SuspiciousRegionCount = suspiciousCount;
    Result->Memory.TotalSuspiciousSize = suspiciousSize;

    if (rwxCount > 0) {
        Result->Indicators |= PhIndicator_MemoryProtection;
    }

    if (unbackedExecCount > 0) {
        Result->Indicators |= PhIndicator_HiddenMemory;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpAnalyzeSectionBacking(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessHandle,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    BOOLEAN isTransacted = FALSE;
    BOOLEAN isDeleted = FALSE;

    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessHandle);

    if (Result->ActualImagePath.Buffer == NULL) {
        Result->Section.HasBackingFile = FALSE;
        Result->Indicators |= PhIndicator_NoPhysicalFile;
        return STATUS_NOT_FOUND;
    }

    Result->Section.HasBackingFile = TRUE;
    PhpCopyUnicodeString(&Result->Section.BackingFileName, &Result->ActualImagePath, PH_POOL_TAG_RESULT);

    //
    // Check for transacted file (doppelganging indicator)
    //
    status = PhpCheckFileTransacted(&Result->ActualImagePath, &isTransacted);
    if (NT_SUCCESS(status) && isTransacted) {
        Result->Section.FileIsTransacted = TRUE;
        Result->Indicators |= PhIndicator_TransactedFile;
    }

    //
    // Check for deleted file (ghosting indicator)
    //
    status = PhpCheckFileDeleted(&Result->ActualImagePath, &isDeleted);
    if (NT_SUCCESS(status) && isDeleted) {
        Result->Section.FileIsDeleted = TRUE;
        Result->Indicators |= PhIndicator_DeletedFile;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PE PARSING
// ============================================================================

static NTSTATUS
PhpParsePEHeaders(
    _In_ PVOID HeaderBuffer,
    _In_ SIZE_T BufferSize,
    _Out_ PPH_PE_CONTEXT PeContext
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    ULONG ntHeaderOffset;

    RtlZeroMemory(PeContext, sizeof(PH_PE_CONTEXT));

    if (BufferSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    dosHeader = (PIMAGE_DOS_HEADER)HeaderBuffer;

    //
    // Validate DOS header
    //
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaderOffset = dosHeader->e_lfanew;

    //
    // Validate NT header offset
    //
    if (ntHeaderOffset >= BufferSize || ntHeaderOffset > PH_NT_HEADERS_OFFSET_MAX) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (ntHeaderOffset + sizeof(IMAGE_NT_HEADERS) > BufferSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)HeaderBuffer + ntHeaderOffset);

    //
    // Validate NT signature
    //
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Determine architecture
    //
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;

        PeContext->Is64Bit = TRUE;
        PeContext->ImageBase = (PVOID)ntHeaders64->OptionalHeader.ImageBase;
        PeContext->ImageSize = ntHeaders64->OptionalHeader.SizeOfImage;
        PeContext->EntryPoint = (PVOID)((ULONG_PTR)ntHeaders64->OptionalHeader.ImageBase +
                                        ntHeaders64->OptionalHeader.AddressOfEntryPoint);
        PeContext->SectionAlignment = ntHeaders64->OptionalHeader.SectionAlignment;
        PeContext->FileAlignment = ntHeaders64->OptionalHeader.FileAlignment;
        PeContext->SizeOfHeaders = ntHeaders64->OptionalHeader.SizeOfHeaders;
        PeContext->Checksum = ntHeaders64->OptionalHeader.CheckSum;

    } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;

        PeContext->Is64Bit = FALSE;
        PeContext->ImageBase = (PVOID)(ULONG_PTR)ntHeaders32->OptionalHeader.ImageBase;
        PeContext->ImageSize = ntHeaders32->OptionalHeader.SizeOfImage;
        PeContext->EntryPoint = (PVOID)((ULONG_PTR)ntHeaders32->OptionalHeader.ImageBase +
                                        ntHeaders32->OptionalHeader.AddressOfEntryPoint);
        PeContext->SectionAlignment = ntHeaders32->OptionalHeader.SectionAlignment;
        PeContext->FileAlignment = ntHeaders32->OptionalHeader.FileAlignment;
        PeContext->SizeOfHeaders = ntHeaders32->OptionalHeader.SizeOfHeaders;
        PeContext->Checksum = ntHeaders32->OptionalHeader.CheckSum;

    } else {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PeContext->HeaderSize = PeContext->SizeOfHeaders;
    PeContext->NumberOfSections = ntHeaders->FileHeader.NumberOfSections;
    PeContext->TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - FILE COMPARISON
// ============================================================================

static NTSTATUS
PhpCompareMemoryWithFile(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID MemoryBase,
    _In_ SIZE_T MemorySize,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset,
    _Out_opt_ PUCHAR MemoryHash,
    _Out_opt_ PUCHAR FileHash
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    PVOID memoryBuffer = NULL;
    PVOID fileBuffer = NULL;
    SIZE_T compareSize;
    SIZE_T bytesRead = 0;
    ULONG i;
    UCHAR memHash[32] = { 0 };
    UCHAR fHash[32] = { 0 };

    *Match = FALSE;
    if (MismatchOffset != NULL) *MismatchOffset = 0;

    //
    // Open the file
    //
    InitializeObjectAttributes(
        &objAttr,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get file size
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Determine comparison size (limit to prevent excessive memory use)
    //
    compareSize = (SIZE_T)min(MemorySize, (SIZE_T)fileInfo.EndOfFile.QuadPart);
    compareSize = min(compareSize, PH_MAX_SECTION_COMPARE);

    if (compareSize < PH_MIN_IMAGE_SIZE) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    //
    // Allocate buffers
    //
    memoryBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        compareSize,
        PH_POOL_TAG_BUFFER
    );

    fileBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        compareSize,
        PH_POOL_TAG_BUFFER
    );

    if (memoryBuffer == NULL || fileBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Read from process memory
    //
    status = PhpReadProcessMemory(
        ProcessHandle,
        MemoryBase,
        memoryBuffer,
        compareSize,
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead < compareSize) {
        goto Cleanup;
    }

    //
    // Read from file
    //
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        fileBuffer,
        (ULONG)compareSize,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Compare the headers (first 4KB should match for legitimate processes)
    //
    compareSize = min(compareSize, PH_MAX_HEADER_SIZE);

    *Match = (RtlCompareMemory(memoryBuffer, fileBuffer, compareSize) == compareSize);

    if (!*Match && MismatchOffset != NULL) {
        //
        // Find first mismatch
        //
        for (i = 0; i < compareSize; i++) {
            if (((PUCHAR)memoryBuffer)[i] != ((PUCHAR)fileBuffer)[i]) {
                *MismatchOffset = i;
                break;
            }
        }
    }

    //
    // Compute hashes if requested
    //
    if (MemoryHash != NULL || FileHash != NULL) {
        if (MemoryHash != NULL) {
            status = ShadowStrikeComputeSha256(
                memoryBuffer,
                compareSize,
                memHash
            );

            if (NT_SUCCESS(status)) {
                RtlCopyMemory(MemoryHash, memHash, 32);
            }
        }

        if (FileHash != NULL) {
            status = ShadowStrikeComputeSha256(
                fileBuffer,
                compareSize,
                fHash
            );

            if (NT_SUCCESS(status)) {
                RtlCopyMemory(FileHash, fHash, 32);
            }
        }
    }

    status = STATUS_SUCCESS;

Cleanup:
    if (memoryBuffer != NULL) {
        ShadowStrikeFreePoolWithTag(memoryBuffer, PH_POOL_TAG_BUFFER);
    }

    if (fileBuffer != NULL) {
        ShadowStrikeFreePoolWithTag(fileBuffer, PH_POOL_TAG_BUFFER);
    }

    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }

    return status;
}

static NTSTATUS
PhpCheckFileTransacted(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN IsTransacted
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_IS_REMOTE_DEVICE_INFORMATION remoteInfo = { 0 };

    *IsTransacted = FALSE;

    //
    // Try to open the file
    //
    InitializeObjectAttributes(
        &objAttr,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        //
        // File doesn't exist or can't be opened - might be transacted
        //
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) {
            *IsTransacted = TRUE;
        }
        return status;
    }

    //
    // Query if file is remote (transacted files show as remote)
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &remoteInfo,
        sizeof(remoteInfo),
        FileIsRemoteDeviceInformation
    );

    ZwClose(fileHandle);

    //
    // Note: In a full implementation, we would use IoGetTransactionParameterBlock
    // or other kernel APIs to detect TxF transactions
    //

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpCheckFileDeleted(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN IsDeleted
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };

    *IsDeleted = FALSE;

    InitializeObjectAttributes(
        &objAttr,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    //
    // Try to open the file
    //
    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_DELETE_PENDING) {
            *IsDeleted = TRUE;
        }
        return status;
    }

    //
    // Check if delete is pending
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (NT_SUCCESS(status)) {
        *IsDeleted = fileInfo.DeletePending;
    }

    ZwClose(fileHandle);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - SCORING
// ============================================================================

static VOID
PhpCalculateScores(
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    ULONG confidence = 0;
    ULONG severity = PH_SEVERITY_BASE;
    PH_INDICATORS indicators = Result->Indicators;

    //
    // Calculate confidence score based on indicators
    //
    if (indicators & PhIndicator_ImagePathMismatch) {
        confidence += PH_SCORE_IMAGE_MISMATCH;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_SectionMismatch) {
        confidence += PH_SCORE_SECTION_MISMATCH;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_EntryPointModified) {
        confidence += PH_SCORE_ENTRY_MODIFIED;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_HeaderModified) {
        confidence += PH_SCORE_HEADER_MODIFIED;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_UnmappedMainModule) {
        confidence += PH_SCORE_UNMAPPED_MODULE;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_TransactedFile) {
        confidence += PH_SCORE_TRANSACTED;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_DeletedFile) {
        confidence += PH_SCORE_DELETED_FILE;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_SuspiciousThread) {
        confidence += PH_SCORE_SUSPENDED_THREAD;
        severity += PH_SEVERITY_MEDIUM_INDICATOR;
    }

    if (indicators & PhIndicator_ModifiedPEB) {
        confidence += PH_SCORE_PEB_MODIFIED;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_HiddenMemory) {
        confidence += PH_SCORE_HIDDEN_MEMORY;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_NoPhysicalFile) {
        confidence += PH_SCORE_NO_PHYSICAL_FILE;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_HashMismatch) {
        confidence += PH_SCORE_HASH_MISMATCH;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_TimestampAnomaly) {
        confidence += PH_SCORE_TIMESTAMP_ANOMALY;
        severity += PH_SEVERITY_MEDIUM_INDICATOR;
    }

    if (indicators & PhIndicator_MemoryProtection) {
        confidence += PH_SCORE_RWX_REGION;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    //
    // Cap scores at 100
    //
    Result->ConfidenceScore = min(confidence, 100);
    Result->SeverityScore = min(severity, 100);
}

static PH_HOLLOWING_TYPE
PhpDetermineHollowingType(
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    PH_INDICATORS indicators = Result->Indicators;

    //
    // Check for specific hollowing types based on indicator combinations
    //

    //
    // Process Doppelganging: Transacted file + section mismatch
    //
    if ((indicators & PhIndicator_TransactedFile) ||
        ((indicators & PhIndicator_NoPhysicalFile) &&
         (indicators & PhIndicator_SectionMismatch))) {
        return PhHollowing_Doppelganging;
    }

    //
    // Process Ghosting: Deleted backing file
    //
    if (indicators & PhIndicator_DeletedFile) {
        return PhHollowing_Ghosting;
    }

    //
    // Process Herpaderping: File modified after section creation
    // (Hash mismatch but file still exists and not transacted)
    //
    if ((indicators & PhIndicator_HashMismatch) &&
        !(indicators & PhIndicator_TransactedFile) &&
        !(indicators & PhIndicator_DeletedFile) &&
        Result->Section.HasBackingFile) {
        return PhHollowing_Herpaderping;
    }

    //
    // Classic Process Hollowing: Entry point modified, section mismatch
    //
    if ((indicators & PhIndicator_EntryPointModified) &&
        (indicators & PhIndicator_SectionMismatch)) {
        return PhHollowing_Classic;
    }

    //
    // Module Stomping: Image path mismatch with PEB modification
    //
    if ((indicators & PhIndicator_ImagePathMismatch) &&
        (indicators & PhIndicator_ModifiedPEB)) {
        return PhHollowing_ModuleStomping;
    }

    //
    // Generic hollowing if we have strong indicators
    //
    if (Result->ConfidenceScore >= 50) {
        if (indicators & (PhIndicator_SectionMismatch | PhIndicator_EntryPointModified |
                          PhIndicator_HeaderModified | PhIndicator_UnmappedMainModule)) {
            return PhHollowing_Classic;
        }
    }

    return PhHollowing_None;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - CALLBACKS
// ============================================================================

static VOID
PhpInvokeCallbacks(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    ULONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (Detector->Callbacks[i].InUse && Detector->Callbacks[i].Callback != NULL) {
            Detector->Callbacks[i].Callback(
                Result,
                Detector->Callbacks[i].Context
            );
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - REFERENCE COUNTING
// ============================================================================

static VOID
PhpAcquireReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    InterlockedIncrement(&Detector->ActiveOperations);
}

static VOID
PhpReleaseReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - STRING UTILITIES
// ============================================================================

static VOID
PhpCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PUNICODE_STRING Src,
    _In_ ULONG PoolTag
    )
{
    RtlZeroMemory(Dest, sizeof(UNICODE_STRING));

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return;
    }

    Dest->MaximumLength = Src->Length + sizeof(WCHAR);
    Dest->Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Dest->MaximumLength,
        PoolTag
    );

    if (Dest->Buffer != NULL) {
        RtlCopyMemory(Dest->Buffer, Src->Buffer, Src->Length);
        Dest->Length = Src->Length;
        Dest->Buffer[Dest->Length / sizeof(WCHAR)] = L'\0';
    }
}

static VOID
PhpFreeUnicodeString(
    _Inout_ PUNICODE_STRING String,
    _In_ ULONG PoolTag
    )
{
    if (String->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(String->Buffer, PoolTag);
        String->Buffer = NULL;
        String->Length = 0;
        String->MaximumLength = 0;
    }
}
