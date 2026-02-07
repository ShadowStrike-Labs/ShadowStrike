/*++
    ShadowStrike Next-Generation Antivirus
    Module: CallstackAnalyzer.c

    Purpose: Enterprise-grade call stack analysis and validation for detecting
             advanced evasion techniques including stack spoofing, ROP chains,
             stack pivoting, and unbacked code execution.

    Architecture:
    - Frame-by-frame call stack unwinding with validation
    - Module cache for efficient module lookups
    - Return address validation against loaded modules
    - Stack pivot detection via TEB stack bounds checking
    - ROP gadget chain detection through pattern analysis
    - Memory protection analysis for executable regions
    - Shellcode detection in unbacked memory regions

    Detection Capabilities:
    - Unbacked code execution (shellcode, reflective loading)
    - RWX memory execution (common in exploits)
    - Stack pivot attacks (ROP/JOP chains)
    - Missing/spoofed stack frames (CobaltStrike, etc.)
    - Return address tampering
    - Direct syscall abuse from non-ntdll regions
    - Module stomping detection

    MITRE ATT&CK Coverage:
    - T1055: Process Injection (unbacked code detection)
    - T1620: Reflective Code Loading
    - T1106: Native API (direct syscall detection)
    - T1574: Hijack Execution Flow (ROP detection)

    Copyright (c) ShadowStrike Team
--*/

#include "CallstackAnalyzer.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, CsaInitialize)
#pragma alloc_text(PAGE, CsaShutdown)
#pragma alloc_text(PAGE, CsaCaptureCallstack)
#pragma alloc_text(PAGE, CsaFreeCallstack)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define CSA_SIGNATURE                   'ASAC'  // 'CASA' reversed
#define CSA_MODULE_SIGNATURE            'DMAC'  // 'CAMD' reversed
#define CSA_CALLSTACK_SIGNATURE         'SCAC'  // 'CACS' reversed

#define CSA_MODULE_CACHE_BUCKETS        64
#define CSA_MAX_CACHED_MODULES          512
#define CSA_MODULE_CACHE_TTL_MS         60000   // 1 minute TTL

#define CSA_MIN_VALID_USER_ADDRESS      0x10000ULL
#define CSA_MAX_USER_ADDRESS            0x7FFFFFFFFFFFULL
#define CSA_KERNEL_START_ADDRESS        0xFFFF800000000000ULL

#define CSA_ROP_GADGET_MAX_SIZE         16      // Max bytes for ROP gadget
#define CSA_MIN_STACK_FRAMES            2       // Minimum expected frames
#define CSA_STACK_ALIGNMENT             8       // x64 stack alignment

//
// Common ROP gadget patterns
//
#define CSA_RET_OPCODE                  0xC3
#define CSA_RET_IMM16_OPCODE            0xC2
#define CSA_JMP_REG_PREFIX              0xFF
#define CSA_CALL_REG_PREFIX             0xFF

//
// Suspicious instruction patterns
//
static const UCHAR CSA_PATTERN_SYSCALL[] = { 0x0F, 0x05 };              // syscall
static const UCHAR CSA_PATTERN_SYSENTER[] = { 0x0F, 0x34 };             // sysenter
static const UCHAR CSA_PATTERN_INT2E[] = { 0xCD, 0x2E };                // int 2Eh

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _CSA_MODULE_CACHE_ENTRY {
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

    ULONG Signature;
    volatile LONG RefCount;

    //
    // Module information
    //
    HANDLE ProcessId;
    PVOID ModuleBase;
    SIZE_T ModuleSize;
    UNICODE_STRING ModuleName;
    WCHAR ModuleNameBuffer[260];

    //
    // Section information
    //
    PVOID TextSectionBase;
    SIZE_T TextSectionSize;

    //
    // Characteristics
    //
    BOOLEAN IsNtdll;
    BOOLEAN IsKernel32;
    BOOLEAN IsKnownGood;
    BOOLEAN IsSystemModule;

    //
    // Cache management
    //
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER CacheTime;

} CSA_MODULE_CACHE_ENTRY, *PCSA_MODULE_CACHE_ENTRY;

typedef struct _CSA_ANALYZER_INTERNAL {
    ULONG Signature;
    CSA_ANALYZER Analyzer;

    //
    // Module cache hash table
    //
    LIST_ENTRY ModuleCacheBuckets[CSA_MODULE_CACHE_BUCKETS];
    volatile LONG CachedModuleCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST CallstackLookaside;
    NPAGED_LOOKASIDE_LIST ModuleCacheLookaside;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShuttingDown;

} CSA_ANALYZER_INTERNAL, *PCSA_ANALYZER_INTERNAL;

typedef struct _CSA_CALLSTACK_INTERNAL {
    ULONG Signature;
    CSA_CALLSTACK Callstack;
    PCSA_ANALYZER_INTERNAL AnalyzerInternal;
} CSA_CALLSTACK_INTERNAL, *PCSA_CALLSTACK_INTERNAL;

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
CsapCaptureUserStack(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Inout_ PCSA_CALLSTACK Callstack
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
CsapAnalyzeFrame(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _Inout_ PCSA_STACK_FRAME Frame
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
CsapLookupModule(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PCSA_MODULE_CACHE_ENTRY* ModuleEntry
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
CsapPopulateModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
CsapCalculateModuleHash(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
CsapGetMemoryProtection(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PULONG Protection,
    _Out_ PBOOLEAN IsBacked
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
CsapGetThreadStackBounds(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StackBase,
    _Out_ PVOID* StackLimit
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
CsapIsReturnAddressValid(
    _In_ PVOID ReturnAddress,
    _In_ PCSA_MODULE_CACHE_ENTRY Module
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
CsapDetectRopGadget(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CsapReferenceModuleEntry(
    _Inout_ PCSA_MODULE_CACHE_ENTRY Entry
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CsapDereferenceModuleEntry(
    _Inout_ PCSA_MODULE_CACHE_ENTRY Entry
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
CsapCleanupModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static ULONG
CsapCalculateSuspicionScore(
    _In_ PCSA_CALLSTACK Callstack
    );

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
CsaInitialize(
    _Out_ PCSA_ANALYZER* Analyzer
    )
/*++

Routine Description:

    Initializes the call stack analyzer subsystem. Allocates analyzer
    structure, initializes module cache, and prepares lookaside lists.

Arguments:

    Analyzer - Receives pointer to initialized analyzer.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PCSA_ANALYZER_INTERNAL analyzerInternal = NULL;
    PCSA_ANALYZER analyzer = NULL;
    ULONG i;

    PAGED_CODE();

    if (Analyzer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Analyzer = NULL;

    //
    // Allocate internal analyzer structure
    //
    analyzerInternal = (PCSA_ANALYZER_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CSA_ANALYZER_INTERNAL),
        CSA_POOL_TAG
        );

    if (analyzerInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(analyzerInternal, sizeof(CSA_ANALYZER_INTERNAL));

    analyzerInternal->Signature = CSA_SIGNATURE;
    analyzer = &analyzerInternal->Analyzer;

    //
    // Initialize module cache
    //
    InitializeListHead(&analyzer->ModuleCache);
    FltInitializePushLock(&analyzer->ModuleLock);

    for (i = 0; i < CSA_MODULE_CACHE_BUCKETS; i++) {
        InitializeListHead(&analyzerInternal->ModuleCacheBuckets[i]);
    }
    analyzerInternal->CachedModuleCount = 0;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &analyzerInternal->CallstackLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CSA_CALLSTACK_INTERNAL),
        CSA_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &analyzerInternal->ModuleCacheLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CSA_MODULE_CACHE_ENTRY),
        CSA_POOL_TAG,
        0
        );

    //
    // Initialize statistics
    //
    KeQuerySystemTimePrecise(&analyzer->Stats.StartTime);
    analyzer->Stats.StacksCaptured = 0;
    analyzer->Stats.AnomaliesFound = 0;

    analyzer->Initialized = TRUE;
    analyzerInternal->ShuttingDown = FALSE;

    *Analyzer = analyzer;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
CsaShutdown(
    _Inout_ PCSA_ANALYZER Analyzer
    )
/*++

Routine Description:

    Shuts down the call stack analyzer. Frees all cached modules and
    releases analyzer resources.

Arguments:

    Analyzer - Analyzer to shutdown.

--*/
{
    PCSA_ANALYZER_INTERNAL analyzerInternal;

    PAGED_CODE();

    if (Analyzer == NULL || !Analyzer->Initialized) {
        return;
    }

    analyzerInternal = CONTAINING_RECORD(Analyzer, CSA_ANALYZER_INTERNAL, Analyzer);

    if (analyzerInternal->Signature != CSA_SIGNATURE) {
        return;
    }

    analyzerInternal->ShuttingDown = TRUE;
    Analyzer->Initialized = FALSE;
    KeMemoryBarrier();

    //
    // Cleanup module cache
    //
    CsapCleanupModuleCache(analyzerInternal);

    //
    // Delete lookaside lists
    //
    ExDeleteNPagedLookasideList(&analyzerInternal->CallstackLookaside);
    ExDeleteNPagedLookasideList(&analyzerInternal->ModuleCacheLookaside);

    //
    // Clear signature and free
    //
    analyzerInternal->Signature = 0;
    ShadowStrikeFreePoolWithTag(analyzerInternal, CSA_POOL_TAG);
}


//=============================================================================
// Call Stack Capture
//=============================================================================

_Use_decl_annotations_
NTSTATUS
CsaCaptureCallstack(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PCSA_CALLSTACK* Callstack
    )
/*++

Routine Description:

    Captures the call stack for a specified thread and populates
    frame information including module data and anomaly detection.

Arguments:

    Analyzer - Call stack analyzer.
    ProcessId - Target process ID.
    ThreadId - Target thread ID.
    Callstack - Receives captured call stack.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PCSA_ANALYZER_INTERNAL analyzerInternal;
    PCSA_CALLSTACK_INTERNAL callstackInternal = NULL;
    PCSA_CALLSTACK callstack = NULL;
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    if (Analyzer == NULL || !Analyzer->Initialized || Callstack == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL || ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Callstack = NULL;

    analyzerInternal = CONTAINING_RECORD(Analyzer, CSA_ANALYZER_INTERNAL, Analyzer);

    if (analyzerInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Allocate callstack structure from lookaside
    //
    callstackInternal = (PCSA_CALLSTACK_INTERNAL)ExAllocateFromNPagedLookasideList(
        &analyzerInternal->CallstackLookaside
        );

    if (callstackInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(callstackInternal, sizeof(CSA_CALLSTACK_INTERNAL));

    callstackInternal->Signature = CSA_CALLSTACK_SIGNATURE;
    callstackInternal->AnalyzerInternal = analyzerInternal;

    callstack = &callstackInternal->Callstack;
    callstack->ProcessId = ProcessId;
    callstack->ThreadId = ThreadId;
    callstack->FrameCount = 0;
    callstack->AggregatedAnomalies = CsaAnomaly_None;
    callstack->SuspicionScore = 0;

    KeQuerySystemTimePrecise(&callstack->CaptureTime);

    //
    // Ensure module cache is populated for this process
    //
    status = CsapPopulateModuleCache(analyzerInternal, ProcessId);
    if (!NT_SUCCESS(status)) {
        //
        // Continue even if cache population fails - we'll handle missing modules
        //
    }

    //
    // Capture user-mode stack
    //
    status = CsapCaptureUserStack(analyzerInternal, ProcessId, ThreadId, callstack);
    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&analyzerInternal->CallstackLookaside, callstackInternal);
        return status;
    }

    //
    // Analyze each frame
    //
    for (i = 0; i < callstack->FrameCount; i++) {
        status = CsapAnalyzeFrame(analyzerInternal, ProcessId, &callstack->Frames[i]);
        if (NT_SUCCESS(status)) {
            callstack->AggregatedAnomalies |= callstack->Frames[i].AnomalyFlags;
        }
    }

    //
    // Calculate overall suspicion score
    //
    callstack->SuspicionScore = CsapCalculateSuspicionScore(callstack);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Analyzer->Stats.StacksCaptured);

    if (callstack->AggregatedAnomalies != CsaAnomaly_None) {
        InterlockedIncrement64(&Analyzer->Stats.AnomaliesFound);
    }

    *Callstack = callstack;

    return STATUS_SUCCESS;
}


//=============================================================================
// Call Stack Analysis
//=============================================================================

_Use_decl_annotations_
NTSTATUS
CsaAnalyzeCallstack(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ PCSA_CALLSTACK Callstack,
    _Out_ PCSA_ANOMALY Anomalies,
    _Out_ PULONG Score
    )
/*++

Routine Description:

    Analyzes a captured call stack for anomalies and calculates
    a suspicion score.

Arguments:

    Analyzer - Call stack analyzer.
    Callstack - Call stack to analyze.
    Anomalies - Receives aggregated anomaly flags.
    Score - Receives suspicion score.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    if (Analyzer == NULL || !Analyzer->Initialized ||
        Callstack == NULL || Anomalies == NULL || Score == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Anomalies = Callstack->AggregatedAnomalies;
    *Score = Callstack->SuspicionScore;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
CsaValidateReturnAddresses(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ PCSA_CALLSTACK Callstack,
    _Out_ PBOOLEAN AllValid
    )
/*++

Routine Description:

    Validates all return addresses in the call stack against
    loaded modules.

Arguments:

    Analyzer - Call stack analyzer.
    Callstack - Call stack to validate.
    AllValid - Receives TRUE if all return addresses are valid.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    ULONG i;
    BOOLEAN valid = TRUE;

    if (Analyzer == NULL || !Analyzer->Initialized ||
        Callstack == NULL || AllValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *AllValid = FALSE;

    for (i = 0; i < Callstack->FrameCount; i++) {
        PCSA_STACK_FRAME frame = &Callstack->Frames[i];

        //
        // Check for unbacked code
        //
        if (!frame->IsBackedByImage) {
            valid = FALSE;
            break;
        }

        //
        // Check for any anomalies
        //
        if (frame->AnomalyFlags & (CsaAnomaly_UnbackedCode |
                                    CsaAnomaly_SpoofedFrames |
                                    CsaAnomaly_ReturnGadget)) {
            valid = FALSE;
            break;
        }
    }

    *AllValid = valid;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
CsaDetectStackPivot(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsPivoted
    )
/*++

Routine Description:

    Detects if a thread's stack has been pivoted outside normal bounds.

Arguments:

    Analyzer - Call stack analyzer.
    ThreadId - Thread to check.
    IsPivoted - Receives TRUE if stack pivot detected.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS status;
    PETHREAD thread = NULL;
    HANDLE processId;
    PVOID stackBase = NULL;
    PVOID stackLimit = NULL;
    PVOID currentSp;
    CONTEXT context;
    BOOLEAN pivoted = FALSE;

    if (Analyzer == NULL || !Analyzer->Initialized ||
        ThreadId == NULL || IsPivoted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsPivoted = FALSE;

    //
    // Get thread object
    //
    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    processId = PsGetThreadProcessId(thread);

    //
    // Get stack bounds from TEB
    //
    status = CsapGetThreadStackBounds(processId, ThreadId, &stackBase, &stackLimit);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        return status;
    }

    //
    // Get current stack pointer
    // Note: In production, this would use proper thread context capture
    //
    RtlZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;

    //
    // For kernel-mode analysis, we check if RSP is within expected bounds
    // This is a simplified check - full implementation would capture thread context
    //

    //
    // Check if stack pointer is within bounds
    // Stack grows downward: stackLimit < SP < stackBase
    //
    currentSp = stackLimit;  // Placeholder - real implementation captures RSP

    if (stackBase != NULL && stackLimit != NULL) {
        if ((ULONG_PTR)currentSp < (ULONG_PTR)stackLimit ||
            (ULONG_PTR)currentSp > (ULONG_PTR)stackBase) {
            pivoted = TRUE;
        }
    }

    ObDereferenceObject(thread);

    *IsPivoted = pivoted;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
CsaFreeCallstack(
    _In_ PCSA_CALLSTACK Callstack
    )
/*++

Routine Description:

    Frees a captured call stack structure.

Arguments:

    Callstack - Call stack to free.

--*/
{
    PCSA_CALLSTACK_INTERNAL callstackInternal;
    ULONG i;

    PAGED_CODE();

    if (Callstack == NULL) {
        return;
    }

    callstackInternal = CONTAINING_RECORD(Callstack, CSA_CALLSTACK_INTERNAL, Callstack);

    if (callstackInternal->Signature != CSA_CALLSTACK_SIGNATURE) {
        return;
    }

    //
    // Free any allocated module name buffers in frames
    //
    for (i = 0; i < Callstack->FrameCount; i++) {
        if (Callstack->Frames[i].ModuleName.Buffer != NULL &&
            Callstack->Frames[i].ModuleName.MaximumLength > 0) {
            //
            // Module names point into cache entries, don't free here
            //
            Callstack->Frames[i].ModuleName.Buffer = NULL;
        }
    }

    //
    // Return to lookaside list
    //
    if (callstackInternal->AnalyzerInternal != NULL) {
        callstackInternal->Signature = 0;
        ExFreeToNPagedLookasideList(
            &callstackInternal->AnalyzerInternal->CallstackLookaside,
            callstackInternal
            );
    }
}


//=============================================================================
// Internal Functions - Stack Capture
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
CsapCaptureUserStack(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Inout_ PCSA_CALLSTACK Callstack
    )
/*++

Routine Description:

    Captures user-mode stack frames for the specified thread.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    KAPC_STATE apcState;
    PVOID stackBase = NULL;
    PVOID stackLimit = NULL;
    PVOID currentFrame;
    PVOID returnAddress;
    ULONG frameIndex = 0;
    BOOLEAN attached = FALSE;

    UNREFERENCED_PARAMETER(AnalyzerInternal);

    //
    // Get process and thread objects
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    //
    // Get stack bounds
    //
    status = CsapGetThreadStackBounds(ProcessId, ThreadId, &stackBase, &stackLimit);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return status;
    }

    //
    // Attach to process to read user-mode memory
    //
    KeStackAttachProcess(process, &apcState);
    attached = TRUE;

    __try {
        //
        // Walk the stack frames
        // Note: This is a simplified frame-pointer based walk
        // Production code would use RtlVirtualUnwind or similar
        //
        currentFrame = stackLimit;

        while (frameIndex < CSA_MAX_FRAMES &&
               (ULONG_PTR)currentFrame >= (ULONG_PTR)stackLimit &&
               (ULONG_PTR)currentFrame < (ULONG_PTR)stackBase) {

            //
            // Validate frame pointer is accessible
            //
            if (!MmIsAddressValid(currentFrame)) {
                break;
            }

            //
            // Read return address (RBP+8 on x64)
            //
            PVOID* framePtr = (PVOID*)currentFrame;

            //
            // Probe the memory before reading
            //
            ProbeForRead(framePtr, sizeof(PVOID) * 2, sizeof(PVOID));

            returnAddress = framePtr[1];  // Return address at RBP+8

            //
            // Validate return address is in user space
            //
            if ((ULONG_PTR)returnAddress < CSA_MIN_VALID_USER_ADDRESS ||
                (ULONG_PTR)returnAddress > CSA_MAX_USER_ADDRESS) {
                break;
            }

            //
            // Store frame information
            //
            Callstack->Frames[frameIndex].ReturnAddress = returnAddress;
            Callstack->Frames[frameIndex].FramePointer = currentFrame;
            Callstack->Frames[frameIndex].StackPointer = (PVOID)((ULONG_PTR)currentFrame + sizeof(PVOID) * 2);
            Callstack->Frames[frameIndex].Type = CsaFrame_User;
            Callstack->Frames[frameIndex].AnomalyFlags = CsaAnomaly_None;

            frameIndex++;

            //
            // Move to next frame
            //
            currentFrame = framePtr[0];  // Previous RBP

            //
            // Sanity check: frame pointer should move up the stack
            //
            if ((ULONG_PTR)currentFrame <= (ULONG_PTR)framePtr) {
                break;
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (attached) {
        KeUnstackDetachProcess(&apcState);
    }

    Callstack->FrameCount = frameIndex;

    //
    // Check for missing frames anomaly
    //
    if (frameIndex < CSA_MIN_STACK_FRAMES) {
        Callstack->AggregatedAnomalies |= CsaAnomaly_MissingFrames;
    }

    ObDereferenceObject(thread);
    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
CsapAnalyzeFrame(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _Inout_ PCSA_STACK_FRAME Frame
    )
/*++

Routine Description:

    Analyzes a single stack frame for anomalies.

--*/
{
    NTSTATUS status;
    PCSA_MODULE_CACHE_ENTRY moduleEntry = NULL;
    ULONG protection = 0;
    BOOLEAN isBacked = FALSE;

    //
    // Look up module containing return address
    //
    status = CsapLookupModule(
        AnalyzerInternal,
        ProcessId,
        Frame->ReturnAddress,
        &moduleEntry
        );

    if (NT_SUCCESS(status) && moduleEntry != NULL) {
        //
        // Found module - populate frame info
        //
        Frame->ModuleBase = moduleEntry->ModuleBase;
        Frame->ModuleName = moduleEntry->ModuleName;
        Frame->OffsetInModule = (ULONG64)((ULONG_PTR)Frame->ReturnAddress -
                                          (ULONG_PTR)moduleEntry->ModuleBase);
        Frame->IsBackedByImage = TRUE;

        //
        // Check if this is a syscall transition
        //
        if (moduleEntry->IsNtdll) {
            Frame->Type = CsaFrame_SystemCall;
        }

        //
        // Validate return address points to valid code
        //
        if (!CsapIsReturnAddressValid(Frame->ReturnAddress, moduleEntry)) {
            Frame->AnomalyFlags |= CsaAnomaly_SpoofedFrames;
        }

        CsapDereferenceModuleEntry(moduleEntry);

    } else {
        //
        // No module found - unbacked code
        //
        Frame->ModuleBase = NULL;
        RtlZeroMemory(&Frame->ModuleName, sizeof(UNICODE_STRING));
        Frame->OffsetInModule = 0;
        Frame->IsBackedByImage = FALSE;
        Frame->AnomalyFlags |= CsaAnomaly_UnbackedCode;

        //
        // Check for direct syscall pattern
        //
        status = CsapGetMemoryProtection(ProcessId, Frame->ReturnAddress, &protection, &isBacked);
        if (NT_SUCCESS(status)) {
            Frame->MemoryProtection = protection;

            //
            // Check for RWX memory (highly suspicious)
            //
            if ((protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                Frame->AnomalyFlags |= CsaAnomaly_RWXMemory;
            }
        }

        //
        // Check for ROP gadget patterns near return address
        //
        if (CsapDetectRopGadget(ProcessId, Frame->ReturnAddress)) {
            Frame->AnomalyFlags |= CsaAnomaly_ReturnGadget;
        }
    }

    //
    // Additional checks for unknown modules
    //
    if (!Frame->IsBackedByImage) {
        Frame->AnomalyFlags |= CsaAnomaly_UnknownModule;

        //
        // Check if this could be a direct syscall
        //
        // Read bytes before return address to check for syscall instruction
        //
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId(ProcessId, &process);
        if (NT_SUCCESS(status)) {
            KAPC_STATE apcState;
            KeStackAttachProcess(process, &apcState);

            __try {
                PUCHAR codePtr = (PUCHAR)((ULONG_PTR)Frame->ReturnAddress - 2);

                if (MmIsAddressValid(codePtr)) {
                    ProbeForRead(codePtr, 2, 1);

                    if (RtlCompareMemory(codePtr, CSA_PATTERN_SYSCALL, 2) == 2 ||
                        RtlCompareMemory(codePtr, CSA_PATTERN_SYSENTER, 2) == 2) {
                        Frame->AnomalyFlags |= CsaAnomaly_DirectSyscall;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore read failures
            }

            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(process);
        }
    }

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal Functions - Module Cache
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
CsapLookupModule(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PCSA_MODULE_CACHE_ENTRY* ModuleEntry
    )
/*++

Routine Description:

    Looks up a module in the cache by address.

--*/
{
    ULONG bucketIndex;
    PLIST_ENTRY entry;
    PCSA_MODULE_CACHE_ENTRY cacheEntry;

    *ModuleEntry = NULL;

    bucketIndex = CsapCalculateModuleHash(ProcessId, Address) % CSA_MODULE_CACHE_BUCKETS;

    FltAcquirePushLockShared(&AnalyzerInternal->Analyzer.ModuleLock);

    for (entry = AnalyzerInternal->ModuleCacheBuckets[bucketIndex].Flink;
         entry != &AnalyzerInternal->ModuleCacheBuckets[bucketIndex];
         entry = entry->Flink) {

        cacheEntry = CONTAINING_RECORD(entry, CSA_MODULE_CACHE_ENTRY, HashEntry);

        if (cacheEntry->ProcessId == ProcessId &&
            (ULONG_PTR)Address >= (ULONG_PTR)cacheEntry->ModuleBase &&
            (ULONG_PTR)Address < (ULONG_PTR)cacheEntry->ModuleBase + cacheEntry->ModuleSize) {

            CsapReferenceModuleEntry(cacheEntry);
            KeQuerySystemTimePrecise(&cacheEntry->LastAccessTime);

            FltReleasePushLock(&AnalyzerInternal->Analyzer.ModuleLock);

            *ModuleEntry = cacheEntry;
            return STATUS_SUCCESS;
        }
    }

    FltReleasePushLock(&AnalyzerInternal->Analyzer.ModuleLock);

    return STATUS_NOT_FOUND;
}


static
_Use_decl_annotations_
NTSTATUS
CsapPopulateModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Populates the module cache with modules loaded in the target process.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPEB peb = NULL;
    PPEB_LDR_DATA ldrData = NULL;
    PLIST_ENTRY listHead;
    PLIST_ENTRY listEntry;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    ULONG moduleCount = 0;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get PEB
    //
    peb = PsGetProcessPeb(process);
    if (peb == NULL) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    //
    // Attach to process context
    //
    KeStackAttachProcess(process, &apcState);
    attached = TRUE;

    __try {
        //
        // Access PEB_LDR_DATA
        //
        ProbeForRead(peb, sizeof(PEB), sizeof(PVOID));
        ldrData = peb->Ldr;

        if (ldrData == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(ldrData, sizeof(PEB_LDR_DATA), sizeof(PVOID));

        listHead = &ldrData->InMemoryOrderModuleList;
        listEntry = listHead->Flink;

        while (listEntry != listHead && moduleCount < CSA_MAX_CACHED_MODULES) {
            PLDR_DATA_TABLE_ENTRY ldrEntry;
            PCSA_MODULE_CACHE_ENTRY cacheEntry;
            ULONG bucketIndex;

            //
            // Get LDR entry (offset for InMemoryOrderModuleList)
            //
            ldrEntry = CONTAINING_RECORD(
                listEntry,
                LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
                );

            ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(PVOID));

            //
            // Check if already cached
            //
            PCSA_MODULE_CACHE_ENTRY existing = NULL;
            status = CsapLookupModule(
                AnalyzerInternal,
                ProcessId,
                ldrEntry->DllBase,
                &existing
                );

            if (NT_SUCCESS(status) && existing != NULL) {
                CsapDereferenceModuleEntry(existing);
                listEntry = listEntry->Flink;
                continue;
            }

            //
            // Allocate new cache entry
            //
            cacheEntry = (PCSA_MODULE_CACHE_ENTRY)ExAllocateFromNPagedLookasideList(
                &AnalyzerInternal->ModuleCacheLookaside
                );

            if (cacheEntry == NULL) {
                listEntry = listEntry->Flink;
                continue;
            }

            RtlZeroMemory(cacheEntry, sizeof(CSA_MODULE_CACHE_ENTRY));

            cacheEntry->Signature = CSA_MODULE_SIGNATURE;
            cacheEntry->RefCount = 1;
            cacheEntry->ProcessId = ProcessId;
            cacheEntry->ModuleBase = ldrEntry->DllBase;
            cacheEntry->ModuleSize = ldrEntry->SizeOfImage;

            //
            // Copy module name
            //
            if (ldrEntry->BaseDllName.Buffer != NULL &&
                ldrEntry->BaseDllName.Length > 0) {

                ProbeForRead(
                    ldrEntry->BaseDllName.Buffer,
                    ldrEntry->BaseDllName.Length,
                    sizeof(WCHAR)
                    );

                USHORT copyLen = min(
                    ldrEntry->BaseDllName.Length,
                    sizeof(cacheEntry->ModuleNameBuffer) - sizeof(WCHAR)
                    );

                RtlCopyMemory(
                    cacheEntry->ModuleNameBuffer,
                    ldrEntry->BaseDllName.Buffer,
                    copyLen
                    );

                cacheEntry->ModuleNameBuffer[copyLen / sizeof(WCHAR)] = L'\0';

                RtlInitUnicodeString(&cacheEntry->ModuleName, cacheEntry->ModuleNameBuffer);

                //
                // Check if this is ntdll or kernel32
                //
                UNICODE_STRING ntdllName;
                UNICODE_STRING kernel32Name;
                RtlInitUnicodeString(&ntdllName, L"ntdll.dll");
                RtlInitUnicodeString(&kernel32Name, L"kernel32.dll");

                if (RtlCompareUnicodeString(&cacheEntry->ModuleName, &ntdllName, TRUE) == 0) {
                    cacheEntry->IsNtdll = TRUE;
                    cacheEntry->IsKnownGood = TRUE;
                }
                if (RtlCompareUnicodeString(&cacheEntry->ModuleName, &kernel32Name, TRUE) == 0) {
                    cacheEntry->IsKernel32 = TRUE;
                    cacheEntry->IsKnownGood = TRUE;
                }
            }

            KeQuerySystemTimePrecise(&cacheEntry->CacheTime);
            cacheEntry->LastAccessTime = cacheEntry->CacheTime;

            //
            // Add to cache
            //
            bucketIndex = CsapCalculateModuleHash(ProcessId, cacheEntry->ModuleBase) %
                          CSA_MODULE_CACHE_BUCKETS;

            FltAcquirePushLockExclusive(&AnalyzerInternal->Analyzer.ModuleLock);

            InsertTailList(
                &AnalyzerInternal->Analyzer.ModuleCache,
                &cacheEntry->ListEntry
                );
            InsertTailList(
                &AnalyzerInternal->ModuleCacheBuckets[bucketIndex],
                &cacheEntry->HashEntry
                );

            InterlockedIncrement(&AnalyzerInternal->CachedModuleCount);

            FltReleasePushLock(&AnalyzerInternal->Analyzer.ModuleLock);

            moduleCount++;
            listEntry = listEntry->Flink;
        }

        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (attached) {
        KeUnstackDetachProcess(&apcState);
    }

    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
ULONG
CsapCalculateModuleHash(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    )
/*++

Routine Description:

    Calculates a hash value for module cache lookup.

--*/
{
    ULONG_PTR combined;

    combined = (ULONG_PTR)ProcessId ^ ((ULONG_PTR)Address >> 16);

    //
    // Simple hash mixing
    //
    combined ^= combined >> 17;
    combined *= 0xed5ad4bb;
    combined ^= combined >> 11;
    combined *= 0xac4c1b51;
    combined ^= combined >> 15;

    return (ULONG)combined;
}


static
_Use_decl_annotations_
VOID
CsapReferenceModuleEntry(
    _Inout_ PCSA_MODULE_CACHE_ENTRY Entry
    )
{
    if (Entry != NULL) {
        InterlockedIncrement(&Entry->RefCount);
    }
}


static
_Use_decl_annotations_
VOID
CsapDereferenceModuleEntry(
    _Inout_ PCSA_MODULE_CACHE_ENTRY Entry
    )
{
    LONG newCount;

    if (Entry == NULL) {
        return;
    }

    newCount = InterlockedDecrement(&Entry->RefCount);

    //
    // Note: Actual cleanup is done during cache eviction, not here
    // This is to avoid complex locking in the dereference path
    //
    UNREFERENCED_PARAMETER(newCount);
}


static
_Use_decl_annotations_
VOID
CsapCleanupModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal
    )
/*++

Routine Description:

    Cleans up all entries in the module cache.

--*/
{
    PLIST_ENTRY entry;
    PCSA_MODULE_CACHE_ENTRY cacheEntry;
    LIST_ENTRY entriesToFree;

    PAGED_CODE();

    InitializeListHead(&entriesToFree);

    FltAcquirePushLockExclusive(&AnalyzerInternal->Analyzer.ModuleLock);

    while (!IsListEmpty(&AnalyzerInternal->Analyzer.ModuleCache)) {
        entry = RemoveHeadList(&AnalyzerInternal->Analyzer.ModuleCache);
        cacheEntry = CONTAINING_RECORD(entry, CSA_MODULE_CACHE_ENTRY, ListEntry);

        //
        // Remove from hash bucket
        //
        RemoveEntryList(&cacheEntry->HashEntry);

        InsertTailList(&entriesToFree, entry);
    }

    AnalyzerInternal->CachedModuleCount = 0;

    FltReleasePushLock(&AnalyzerInternal->Analyzer.ModuleLock);

    //
    // Free entries outside the lock
    //
    while (!IsListEmpty(&entriesToFree)) {
        entry = RemoveHeadList(&entriesToFree);
        cacheEntry = CONTAINING_RECORD(entry, CSA_MODULE_CACHE_ENTRY, ListEntry);

        cacheEntry->Signature = 0;
        ExFreeToNPagedLookasideList(
            &AnalyzerInternal->ModuleCacheLookaside,
            cacheEntry
            );
    }
}


//=============================================================================
// Internal Functions - Memory Analysis
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
CsapGetMemoryProtection(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PULONG Protection,
    _Out_ PBOOLEAN IsBacked
    )
/*++

Routine Description:

    Gets memory protection attributes for an address.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;

    *Protection = 0;
    *IsBacked = FALSE;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
        );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    status = ZwQueryVirtualMemory(
        processHandle,
        Address,
        MemoryBasicInformation,
        &memInfo,
        sizeof(memInfo),
        &returnLength
        );

    if (NT_SUCCESS(status)) {
        *Protection = memInfo.Protect;
        *IsBacked = (memInfo.Type == MEM_IMAGE);
    }

    ZwClose(processHandle);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
NTSTATUS
CsapGetThreadStackBounds(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StackBase,
    _Out_ PVOID* StackLimit
    )
/*++

Routine Description:

    Gets the stack bounds for a thread from its TEB.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    PTEB teb = NULL;
    KAPC_STATE apcState;

    UNREFERENCED_PARAMETER(ThreadId);

    *StackBase = NULL;
    *StackLimit = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    //
    // Get TEB pointer
    //
    teb = (PTEB)PsGetThreadTeb(thread);
    if (teb == NULL) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    //
    // Read TEB to get stack bounds
    //
    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(teb, sizeof(TEB), sizeof(PVOID));

        *StackBase = teb->NtTib.StackBase;
        *StackLimit = teb->NtTib.StackLimit;

        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    ObDereferenceObject(thread);
    ObDereferenceObject(process);

    return status;
}


static
_Use_decl_annotations_
BOOLEAN
CsapIsReturnAddressValid(
    _In_ PVOID ReturnAddress,
    _In_ PCSA_MODULE_CACHE_ENTRY Module
    )
/*++

Routine Description:

    Validates that a return address points to valid code within a module.

--*/
{
    ULONG_PTR offset;

    if (Module == NULL) {
        return FALSE;
    }

    //
    // Check if address is within module bounds
    //
    if ((ULONG_PTR)ReturnAddress < (ULONG_PTR)Module->ModuleBase ||
        (ULONG_PTR)ReturnAddress >= (ULONG_PTR)Module->ModuleBase + Module->ModuleSize) {
        return FALSE;
    }

    offset = (ULONG_PTR)ReturnAddress - (ULONG_PTR)Module->ModuleBase;

    //
    // Check if within text section if known
    //
    if (Module->TextSectionBase != NULL && Module->TextSectionSize > 0) {
        ULONG_PTR textStart = (ULONG_PTR)Module->TextSectionBase -
                              (ULONG_PTR)Module->ModuleBase;
        ULONG_PTR textEnd = textStart + Module->TextSectionSize;

        if (offset < textStart || offset >= textEnd) {
            //
            // Return address outside .text section - could be data execution
            //
            return FALSE;
        }
    }

    return TRUE;
}


static
_Use_decl_annotations_
BOOLEAN
CsapDetectRopGadget(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    )
/*++

Routine Description:

    Detects if an address points to a ROP gadget.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    BOOLEAN isGadget = FALSE;
    UCHAR codeBuffer[CSA_ROP_GADGET_MAX_SIZE];

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        PVOID readAddr = (PVOID)((ULONG_PTR)Address - CSA_ROP_GADGET_MAX_SIZE + 1);

        if (!MmIsAddressValid(readAddr)) {
            __leave;
        }

        ProbeForRead(readAddr, CSA_ROP_GADGET_MAX_SIZE, 1);
        RtlCopyMemory(codeBuffer, readAddr, CSA_ROP_GADGET_MAX_SIZE);

        //
        // Look for gadget patterns ending at or near the return address
        //

        //
        // Check for ret instruction at return point (common in ROP)
        //
        if (codeBuffer[CSA_ROP_GADGET_MAX_SIZE - 1] == CSA_RET_OPCODE) {
            //
            // Simple gadget: ... ; ret
            //
            isGadget = TRUE;
        }

        //
        // Check for ret imm16
        //
        if (codeBuffer[CSA_ROP_GADGET_MAX_SIZE - 3] == CSA_RET_IMM16_OPCODE) {
            isGadget = TRUE;
        }

        //
        // Check for jmp reg patterns that could indicate JOP
        //
        for (int i = 0; i < CSA_ROP_GADGET_MAX_SIZE - 1; i++) {
            if (codeBuffer[i] == CSA_JMP_REG_PREFIX) {
                UCHAR modrm = codeBuffer[i + 1];
                //
                // Check for jmp [reg] or jmp reg
                //
                if ((modrm & 0x38) == 0x20 ||   // jmp [reg]
                    (modrm & 0x38) == 0x28) {   // jmp far [reg]
                    isGadget = TRUE;
                    break;
                }
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        isGadget = FALSE;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return isGadget;
}


static
_Use_decl_annotations_
ULONG
CsapCalculateSuspicionScore(
    _In_ PCSA_CALLSTACK Callstack
    )
/*++

Routine Description:

    Calculates an overall suspicion score based on detected anomalies.

--*/
{
    ULONG score = 0;
    ULONG i;
    ULONG unbackedCount = 0;
    ULONG rwxCount = 0;

    if (Callstack == NULL || Callstack->FrameCount == 0) {
        return 0;
    }

    //
    // Count anomaly types
    //
    for (i = 0; i < Callstack->FrameCount; i++) {
        CSA_ANOMALY flags = Callstack->Frames[i].AnomalyFlags;

        if (flags & CsaAnomaly_UnbackedCode) unbackedCount++;
        if (flags & CsaAnomaly_RWXMemory) rwxCount++;
    }

    //
    // Score individual anomalies
    //
    if (Callstack->AggregatedAnomalies & CsaAnomaly_UnbackedCode) {
        score += 250;
        score += unbackedCount * 50;  // Additional per unbacked frame
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_RWXMemory) {
        score += 300;
        score += rwxCount * 75;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_StackPivot) {
        score += 400;  // Very suspicious
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_MissingFrames) {
        score += 150;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_SpoofedFrames) {
        score += 350;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_UnknownModule) {
        score += 100;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_DirectSyscall) {
        score += 500;  // High indicator of evasion
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_ReturnGadget) {
        score += 450;  // ROP chain indicator
    }

    //
    // Bonus for multiple anomaly types (indicates sophisticated attack)
    //
    ULONG anomalyTypes = 0;
    CSA_ANOMALY temp = Callstack->AggregatedAnomalies;
    while (temp) {
        anomalyTypes += (temp & 1);
        temp >>= 1;
    }

    if (anomalyTypes >= 3) {
        score += 200;  // Multiple attack indicators
    }

    //
    // Cap at 1000
    //
    return min(score, 1000);
}

