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
#include "../Core/Globals.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PH_VERSION                      1
#define PH_MAX_CALLBACKS                8
#define PH_MAX_SECTION_COMPARE          (64 * 1024)
#define PH_MIN_IMAGE_SIZE               512
#define PH_ENTRY_POINT_SCAN_SIZE        64
#define PH_DOS_HEADER_SIZE              64
#define PH_NT_HEADERS_OFFSET_MAX        1024
#define PH_SHUTDOWN_TIMEOUT_100NS       (-(LONGLONG)10 * 1000 * 10000)  // 10 seconds

C_ASSERT(PH_MAX_SECTION_COMPARE <= (SIZE_T)MAXULONG);  // L-2: ZwReadFile ULONG cast safety

//
// CAS-based lifecycle states (C-1, H-1, H-5 fix)
//
#define PH_STATE_UNINITIALIZED          0
#define PH_STATE_INITIALIZING           1
#define PH_STATE_READY                  2
#define PH_STATE_SHUTTING_DOWN          3

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
 * @brief Extended internal detector structure.
 *
 * Uses CAS-based state machine for lifecycle management.
 * Public PH_DETECTOR is embedded as first member for
 * CONTAINING_RECORD access from callers.
 */
typedef struct _PH_DETECTOR_INTERNAL {
    //
    // Base public structure
    //
    PH_DETECTOR Public;

    //
    // Lifecycle state (CAS-based: PH_STATE_*)
    //
    volatile LONG State;

    //
    // Callback management
    //
    PH_CALLBACK_ENTRY Callbacks[PH_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    //
    // Shutdown synchronization
    //
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

//
// C-5 fix: Declare ShadowStrikeGetProcessImageBase if not available
// from ProcessUtils.h. This must be implemented elsewhere.
//
#ifndef SHADOWSTRIKE_GET_PROCESS_IMAGE_BASE_DECLARED
NTSTATUS
ShadowStrikeGetProcessImageBase(
    _In_ PEPROCESS Process,
    _Out_ PVOID* ImageBase,
    _Out_ PSIZE_T ImageSize
    );
#define SHADOWSTRIKE_GET_PROCESS_IMAGE_BASE_DECLARED
#endif

static PPH_ANALYSIS_RESULT
PhpAllocateResult(
    VOID
    );

static VOID
PhpFreeResultInternal(
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

/**
 * @brief Atomically acquire a reference. Returns FALSE if shutting down.
 * (C-1, H-1 fix: increment-then-check pattern prevents use-after-free)
 */
static BOOLEAN
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

/**
 * @brief Inline state check for ready state.
 */
static FORCEINLINE BOOLEAN
PhpIsReady(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    return (ReadAcquire(&Detector->State) == PH_STATE_READY);
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhInitialize(
    _Out_ PPH_DETECTOR* Detector
    )
{
    PPH_DETECTOR_INTERNAL internal = NULL;
    LONG previousState;

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

    //
    // CAS state: UNINITIALIZED -> INITIALIZING (C-1 fix)
    //
    previousState = InterlockedCompareExchange(
        &internal->State,
        PH_STATE_INITIALIZING,
        PH_STATE_UNINITIALIZED
    );

    if (previousState != PH_STATE_UNINITIALIZED) {
        ShadowStrikeFreePoolWithTag(internal, PH_POOL_TAG_CONTEXT);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&internal->CallbackLock);

    //
    // Initialize shutdown synchronization
    //
    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // Init reference — released by PhShutdown

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
    // Transition: INITIALIZING -> READY
    //
    MemoryBarrier();
    InterlockedExchange(&internal->State, PH_STATE_READY);

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
    LARGE_INTEGER timeout;
    LONG previousState;

    if (Detector == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    //
    // CAS state: READY -> SHUTTING_DOWN (C-1 fix)
    //
    previousState = InterlockedCompareExchange(
        &internal->State,
        PH_STATE_SHUTTING_DOWN,
        PH_STATE_READY
    );

    if (previousState != PH_STATE_READY) {
        return;
    }

    //
    // Release init reference and wait for active operations to drain.
    // Bounded timeout prevents infinite hang.
    //
    PhpReleaseReference(internal);
    timeout.QuadPart = PH_SHUTDOWN_TIMEOUT_100NS;
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Final state transition and free
    //
    InterlockedExchange(&internal->State, PH_STATE_UNINITIALIZED);

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

    if (Detector == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

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
    // Allocate result structure (C-4 fix: always use pool alloc for
    // results returned to callers via public API, never lookaside,
    // so PhFreeResult can safely free with ShadowStrikeFreePoolWithTag)
    //
    result = PhpAllocateResult();
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
        PhpFreeResultInternal(result);
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

    if (Detector == NULL || Process == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQuerySystemTime(&startTime);

    //
    // M-5 fix: Use ObReferenceObjectSafe to handle dying process objects
    //
    if (!ObReferenceObjectSafe(Process)) {
        PhpReleaseReference(internal);
        return STATUS_PROCESS_IS_TERMINATING;
    }

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
    // Allocate result (C-4 fix: pool alloc, not lookaside)
    //
    result = PhpAllocateResult();
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));
    result->ProcessId = ProcessId;
    result->AnalysisTime = startTime;

    //
    // Get process creation time (C-3 fix: .QuadPart assignment)
    //
    result->ProcessCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

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
        PhpFreeResultInternal(result);
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

    if (Detector == NULL || Match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Match = FALSE;
    if (MismatchOffset != NULL) *MismatchOffset = 0;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

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
    PhpFreeUnicodeString(&imagePath, PH_POOL_TAG_RESULT);

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

    if (Detector == NULL || Valid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Valid = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

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
    result = PhpAllocateResult();
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
        PhpFreeResultInternal(result);
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

    if (Detector == NULL || IsDoppelganging == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsDoppelganging = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

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
    PhpFreeUnicodeString(&imagePath, PH_POOL_TAG_RESULT);

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

    if (Detector == NULL || IsGhosting == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsGhosting = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

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
    PhpFreeUnicodeString(&imagePath, PH_POOL_TAG_RESULT);

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

    if (Detector == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpIsReady(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

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

    if (Detector == NULL || Callback == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpIsReady(internal)) {
        return;
    }

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

    if (Detector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // L-3: Statistics reads are intentionally non-atomic (approximate).
    // InterlockedIncrement64 is used for writes; plain reads may see
    // slightly stale values, which is acceptable for diagnostic counters.
    //
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

//
// C-4 fix: Always use pool alloc (never lookaside) for results returned
// to callers. This eliminates the free-mismatch between PhFreeResult
// (pool free) and PhpFreeResultInternal (was conditionally lookaside).
//
static PPH_ANALYSIS_RESULT
PhpAllocateResult(
    VOID
    )
{
    return (PPH_ANALYSIS_RESULT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PH_ANALYSIS_RESULT),
        PH_POOL_TAG_RESULT
    );
}

static VOID
PhpFreeResultInternal(
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

    ShadowStrikeFreePoolWithTag(Result, PH_POOL_TAG_RESULT);
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
    // Copy the string (H-8 fix: use PH_POOL_TAG_RESULT since this string
    // will be owned by the result and freed by PhFreeResult with that tag)
    //
    PhpCopyUnicodeString(ImagePath, processImageName, PH_POOL_TAG_RESULT);

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
    // M-3 fix: Calculate entry point RVA with overflow protection.
    // peContext.EntryPoint is stored as (ImageBase + AddressOfEntryPoint),
    // so the RVA = peContext.EntryPoint - peContext.ImageBase.
    // Validate the pointer arithmetic won't wrap.
    //
    if ((ULONG_PTR)peContext.EntryPoint < (ULONG_PTR)peContext.ImageBase) {
        //
        // Malicious PE: EntryPoint < ImageBase means negative RVA (wrapped)
        //
        Result->EntryPoint.DeclaredEntryPoint = peContext.EntryPoint;
        Result->EntryPoint.ActualEntryPoint = NULL;
        Result->EntryPoint.EntryPointInImage = FALSE;
        Result->EntryPoint.EntryPointExecutable = FALSE;
        Result->EntryPoint.EntryPointValid = FALSE;
        Result->Indicators |= PhIndicator_EntryPointModified;
        ShadowStrikeFreePoolWithTag(headerBuffer, PH_POOL_TAG_BUFFER);
        return STATUS_SUCCESS;
    }

    {
        ULONG_PTR rva = (ULONG_PTR)peContext.EntryPoint - (ULONG_PTR)peContext.ImageBase;

        Result->EntryPoint.DeclaredEntryPoint = peContext.EntryPoint;
        Result->EntryPoint.ActualEntryPoint = (PVOID)((ULONG_PTR)imageBase + rva);

        //
        // Validate entry point is within image bounds
        //
        Result->EntryPoint.EntryPointInImage =
            (rva < imageSize) &&
            ((ULONG_PTR)Result->EntryPoint.ActualEntryPoint >= (ULONG_PTR)imageBase);
    }

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
    //
    // H-6 fix: Validate peb.ProcessParameters is a user-mode address.
    // A hostile process can point this into kernel space.
    //
    if (peb.ProcessParameters != NULL && ShadowStrikeIsUserAddress(peb.ProcessParameters)) {
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
            // H-6 fix: Also validate params.ImagePathName.Buffer is user-mode
            //
            if (params.ImagePathName.Length > 0 &&
                params.ImagePathName.Length < MAX_PATH * sizeof(WCHAR) &&
                params.ImagePathName.Buffer != NULL &&
                ShadowStrikeIsUserAddress(params.ImagePathName.Buffer)) {

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
            // L-1 fix: use 'else if' to prevent double-counting.
            // A region that is RWX+private was already counted above.
            //
            else if (isExecutable && memInfo.Type == MEM_PRIVATE) {
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

    //
    // C-6 fix: Initial bounds check uses Signature + FileHeader only.
    // The full architecture-specific check comes after we read the magic.
    //
    if (ntHeaderOffset + RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS, FileHeader) > BufferSize) {
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
    // Need at least Magic field to determine architecture
    //
    if (ntHeaderOffset + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.Magic) + sizeof(USHORT) > BufferSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Determine architecture — C-6 fix: re-validate bounds for the specific
    // header size BEFORE accessing any optional header fields
    //
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 ntHeaders64;

        if (ntHeaderOffset + sizeof(IMAGE_NT_HEADERS64) > BufferSize) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;

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
        PIMAGE_NT_HEADERS32 ntHeaders32;

        if (ntHeaderOffset + sizeof(IMAGE_NT_HEADERS32) > BufferSize) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;

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
    // H-2 fix: Use PagedPool — this function runs at PASSIVE_LEVEL only,
    // and allocations can be up to PH_MAX_SECTION_COMPARE (256KB).
    // H-3 fix: Compare the FULL allocated range, not just 4KB. The old
    // truncation to PH_MAX_HEADER_SIZE made detection trivially evadable.
    //
    memoryBuffer = ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        compareSize,
        PH_POOL_TAG_BUFFER
    );

    fileBuffer = ShadowStrikeAllocatePoolWithTag(
        PagedPool,
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
    // H-3 fix: Compare the full allocated range, not just first 4KB.
    // An attacker modifying code beyond 4KB would otherwise evade detection.
    //
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
    PFILE_OBJECT fileObject = NULL;
    PTRANSACTION_PARAMETER_BLOCK txnParams = NULL;

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
        // File doesn't exist — possible rolled-back TxF transaction.
        // This is a strong doppelganging indicator: the process image
        // was created from a transacted file that was subsequently rolled back.
        //
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) {
            *IsTransacted = TRUE;
            return STATUS_SUCCESS;
        }
        return status;
    }

    //
    // Get the FILE_OBJECT and check for active transaction via
    // IoGetTransactionParameterBlock. This detects process doppelganging
    // where the file is still within an active TxF transaction.
    //
    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL
    );

    if (NT_SUCCESS(status)) {
        txnParams = IoGetTransactionParameterBlock(fileObject);
        if (txnParams != NULL) {
            //
            // File is part of an active transaction — strong doppelganging indicator
            //
            *IsTransacted = TRUE;
        }
        ObDereferenceObject(fileObject);
    }

    ZwClose(fileHandle);

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
    ULONG count = 0;

    //
    // H-4 fix: Copy callbacks under lock, then invoke outside lock.
    // This prevents deadlock if a callback calls PhUnregisterCallback
    // (which takes exclusive lock on the same push lock).
    //
    struct {
        PH_DETECTION_CALLBACK Callback;
        PVOID Context;
    } snapshot[PH_MAX_CALLBACKS];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (Detector->Callbacks[i].InUse && Detector->Callbacks[i].Callback != NULL) {
            snapshot[count].Callback = Detector->Callbacks[i].Callback;
            snapshot[count].Context = Detector->Callbacks[i].Context;
            count++;
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Invoke outside the lock — safe from deadlock
    //
    for (i = 0; i < count; i++) {
        snapshot[i].Callback(Result, snapshot[i].Context);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - REFERENCE COUNTING
// ============================================================================

//
// H-1 fix: PhpAcquireReference returns BOOLEAN. Increment first,
// then check if state is READY. If not, decrement and signal event.
// This eliminates the TOCTOU between the state check and increment.
//
static BOOLEAN
PhpAcquireReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    InterlockedIncrement(&Detector->ActiveOperations);

    if (ReadAcquire(&Detector->State) == PH_STATE_READY) {
        return TRUE;
    }

    //
    // Not ready (shutting down or not initialized) — roll back
    //
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
    return FALSE;
}

static VOID
PhpReleaseReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        //
        // Only signal if we're shutting down — avoid spurious wakeups
        //
        if (ReadAcquire(&Detector->State) == PH_STATE_SHUTTING_DOWN) {
            KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        }
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
    //
    // M-2 fix: Use PagedPool — all callers run at PASSIVE_LEVEL and
    // these are file path strings. Saves NonPagedPool pressure.
    //
    Dest->Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
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
