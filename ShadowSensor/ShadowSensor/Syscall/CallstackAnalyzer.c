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
    ShadowStrike Next-Generation Antivirus
    Module: CallstackAnalyzer.c

    Purpose: Enterprise-grade call stack analysis and validation for detecting
             advanced evasion techniques including stack spoofing, ROP chains,
             stack pivoting, and unbacked code execution.

    Architecture:
    - User-mode stack capture via RtlWalkFrameChain (flag=1) while attached
    - Module cache with PID+CreateTime keying for PID-reuse safety
    - Return address validation against loaded modules
    - Stack pivot detection via TEB stack bounds vs. captured RSP
    - ROP gadget chain detection through short-sequence pattern analysis
    - Memory protection analysis for executable regions
    - Shellcode detection in unbacked memory regions
    - Refcount-based shutdown drain (follows AnomalyDetector pattern)
    - Ex*PushLock with KeEnterCriticalRegion (codebase convention)

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
#include "../../Shared/KernelProcessTypes.h"
#include <ntimage.h>

//
// User-mode constants not exposed in WDK kernel headers.
// Values are stable across all Windows NT versions.
//
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif

#ifndef MEM_IMAGE
#define MEM_IMAGE                   0x1000000
#endif

//
// PsGetThreadTeb — returns the user-mode TEB address of a thread.
// Exported by ntoskrnl.exe, not declared in WDK headers (NT 6.0+).
//
NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb(
    _In_ PETHREAD Thread
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CsaInitialize)
#pragma alloc_text(PAGE, CsaShutdown)
#pragma alloc_text(PAGE, CsaCaptureCallstack)
#pragma alloc_text(PAGE, CsaFreeCallstack)
#pragma alloc_text(PAGE, CsaOnProcessExit)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define CSA_SIGNATURE                   'ASAC'
#define CSA_MODULE_SIGNATURE            'DMAC'
#define CSA_CALLSTACK_SIGNATURE         'SCAC'

#define CSA_MAX_CACHED_MODULES          512
#define CSA_MODULE_CACHE_TTL_100NS      (60LL * 10000000LL)  // 1 minute in 100ns units

#define CSA_MIN_VALID_USER_ADDRESS      0x10000ULL
#define CSA_MAX_USER_ADDRESS            0x7FFFFFFFFFFFULL

#define CSA_ROP_GADGET_WINDOW           8       // Max bytes before address for gadget analysis
#define CSA_MIN_STACK_FRAMES            2
#define CSA_MAX_MODULE_SIZE             0x80000000ULL  // 2 GB sanity cap

#define CSA_SHUTDOWN_DRAIN_TIMEOUT_MS   5000

//
// Throttle: max captures per second across all threads
//
#define CSA_MAX_CAPTURES_PER_SECOND     200
#define CSA_THROTTLE_WINDOW_100NS       (10000000LL)  // 1 second

//
// Common ROP gadget patterns
//
#define CSA_RET_OPCODE                  0xC3
#define CSA_RET_IMM16_OPCODE            0xC2

//
// Suspicious instruction patterns
//
static const UCHAR CsaPatternSyscall[]  = { 0x0F, 0x05 };
static const UCHAR CsaPatternSysenter[] = { 0x0F, 0x34 };

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _CSA_MODULE_CACHE_ENTRY {
    LIST_ENTRY ListEntry;

    ULONG Signature;
    volatile LONG RefCount;

    HANDLE ProcessId;
    LONGLONG ProcessCreateTime;  // PID-reuse protection
    PVOID ModuleBase;
    SIZE_T ModuleSize;
    UNICODE_STRING ModuleName;
    WCHAR ModuleNameBuffer[CSA_MAX_MODULE_NAME_CCH];

    PVOID TextSectionBase;
    SIZE_T TextSectionSize;

    BOOLEAN IsNtdll;
    BOOLEAN IsKernel32;
    BOOLEAN IsKnownGood;
    BOOLEAN IsSystemModule;

    LARGE_INTEGER CacheTime;
} CSA_MODULE_CACHE_ENTRY, *PCSA_MODULE_CACHE_ENTRY;

typedef struct _CSA_ANALYZER_INTERNAL {
    ULONG Signature;
    CSA_ANALYZER Public;

    NPAGED_LOOKASIDE_LIST CallstackLookaside;
    NPAGED_LOOKASIDE_LIST ModuleCacheLookaside;

    volatile LONG CachedModuleCount;
    volatile BOOLEAN ShuttingDown;

    //
    // Throttle state
    //
    volatile LONG64 CaptureWindowStart;
    volatile LONG CapturesInWindow;
} CSA_ANALYZER_INTERNAL, *PCSA_ANALYZER_INTERNAL;

typedef struct _CSA_CALLSTACK_INTERNAL {
    ULONG Signature;
    CSA_CALLSTACK Callstack;
    PCSA_ANALYZER_INTERNAL AnalyzerRef;
} CSA_CALLSTACK_INTERNAL, *PCSA_CALLSTACK_INTERNAL;

//
// Temporary structure for batched user-mode reads during module cache population.
// Holds data copied out of the target process address space so that lock
// acquisition never occurs inside a __try block touching user memory.
//
#define CSA_MAX_MODULES_PER_POPULATE 128

typedef struct _CSA_MODULE_SNAPSHOT_ENTRY {
    PVOID DllBase;
    SIZE_T SizeOfImage;
    WCHAR BaseDllName[CSA_MAX_MODULE_NAME_CCH];
    USHORT NameLength;  // bytes, not chars
    BOOLEAN Valid;
} CSA_MODULE_SNAPSHOT_ENTRY, *PCSA_MODULE_SNAPSHOT_ENTRY;

//=============================================================================
// Forward Declarations
//=============================================================================

static VOID CsapReferenceAnalyzer(_Inout_ PCSA_ANALYZER_INTERNAL Internal);
static VOID CsapDereferenceAnalyzer(_Inout_ PCSA_ANALYZER_INTERNAL Internal);

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CsapCaptureUserStack(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Inout_ PCSA_CALLSTACK Callstack
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CsapAnalyzeFrames(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _Inout_ PCSA_CALLSTACK Callstack
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CsapLookupModule(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ LONGLONG ProcessCreateTime,
    _In_ PVOID Address,
    _Out_ PCSA_MODULE_CACHE_ENTRY* ModuleEntry
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CsapPopulateModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ LONGLONG ProcessCreateTime
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CsapGetMemoryProtection(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PULONG Protection,
    _Out_ PBOOLEAN IsBacked
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CsapGetThreadStackBounds(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StackBase,
    _Out_ PVOID* StackLimit
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
CsapIsReturnAddressValid(
    _In_ PVOID ReturnAddress,
    _In_ PCSA_MODULE_CACHE_ENTRY Module
    );

_IRQL_requires_(PASSIVE_LEVEL)
static CSA_ANOMALY
CsapAnalyzeUnbackedCode(
    _In_ PEPROCESS Process,
    _In_ PVOID Address
    );

static VOID CsapReferenceModuleEntry(_Inout_ PCSA_MODULE_CACHE_ENTRY Entry);
static VOID CsapDereferenceModuleEntry(_Inout_ PCSA_MODULE_CACHE_ENTRY Entry);

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
CsapCleanupModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
CsapEvictProcessEntries(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId
    );

static ULONG
CsapCalculateSuspicionScore(
    _In_ PCSA_CALLSTACK Callstack
    );

static VOID
CsapPopulateTextSection(
    _In_ PEPROCESS Process,
    _Inout_ PCSA_MODULE_CACHE_ENTRY CacheEntry
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
CsapThrottleCheck(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal
    );

//=============================================================================
// Analyzer Reference Counting
//=============================================================================

static
VOID
CsapReferenceAnalyzer(
    _Inout_ PCSA_ANALYZER_INTERNAL Internal
    )
{
    InterlockedIncrement(&Internal->Public.RefCount);
}

static
VOID
CsapDereferenceAnalyzer(
    _Inout_ PCSA_ANALYZER_INTERNAL Internal
    )
{
    LONG newCount = InterlockedDecrement(&Internal->Public.RefCount);
    if (newCount == 0) {
        KeSetEvent(&Internal->Public.ZeroRefEvent, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
CsaInitialize(
    _Out_ PCSA_ANALYZER* Analyzer
    )
{
    PCSA_ANALYZER_INTERNAL analyzerInternal = NULL;
    PCSA_ANALYZER analyzer = NULL;

    PAGED_CODE();

    if (Analyzer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Analyzer = NULL;

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
    analyzer = &analyzerInternal->Public;

    InitializeListHead(&analyzer->ModuleCache);
    ExInitializePushLock(&analyzer->ModuleLock);

    //
    // RefCount starts at 1 — the "owner" reference released by CsaShutdown.
    //
    analyzer->RefCount = 1;
    KeInitializeEvent(&analyzer->ZeroRefEvent, NotificationEvent, FALSE);

    analyzerInternal->CachedModuleCount = 0;
    analyzerInternal->ShuttingDown = FALSE;
    analyzerInternal->CapturesInWindow = 0;

    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    analyzerInternal->CaptureWindowStart = now.QuadPart;

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

    KeQuerySystemTimePrecise(&analyzer->Stats.StartTime);
    analyzer->Stats.StacksCaptured = 0;
    analyzer->Stats.AnomaliesFound = 0;

    analyzer->Initialized = TRUE;

    *Analyzer = analyzer;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
CsaShutdown(
    _Inout_ PCSA_ANALYZER Analyzer
    )
{
    PCSA_ANALYZER_INTERNAL analyzerInternal;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    PAGED_CODE();

    if (Analyzer == NULL || !Analyzer->Initialized) {
        return;
    }

    analyzerInternal = CONTAINING_RECORD(Analyzer, CSA_ANALYZER_INTERNAL, Public);

    if (analyzerInternal->Signature != CSA_SIGNATURE) {
        return;
    }

    //
    // Signal shutdown. New operations will be rejected.
    //
    analyzerInternal->ShuttingDown = TRUE;
    Analyzer->Initialized = FALSE;
    KeMemoryBarrier();

    //
    // Release the owner reference and wait for all outstanding operations
    // to complete (refs from CsaCaptureCallstack, CsaFreeCallstack, etc.).
    // Clear the event BEFORE decrementing to prevent TOCTOU: if the last
    // ref drops between decrement and wait, KeSetEvent is not lost.
    //
    KeClearEvent(&Analyzer->ZeroRefEvent);
    CsapDereferenceAnalyzer(analyzerInternal);

    timeout.QuadPart = -((LONGLONG)CSA_SHUTDOWN_DRAIN_TIMEOUT_MS * 10000);
    waitStatus = KeWaitForSingleObject(
        &Analyzer->ZeroRefEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
        );

    if (waitStatus == STATUS_TIMEOUT) {
        //
        // Outstanding references did not drain in time. This is a bug in
        // the caller, but proceeding is safer than leaking the structure.
        // Log for diagnostics.
        //
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-CSA] WARNING: Shutdown drain timed out, RefCount=%ld\n",
            Analyzer->RefCount);
    }

    CsapCleanupModuleCache(analyzerInternal);

    ExDeleteNPagedLookasideList(&analyzerInternal->CallstackLookaside);
    ExDeleteNPagedLookasideList(&analyzerInternal->ModuleCacheLookaside);

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
{
    PCSA_ANALYZER_INTERNAL analyzerInternal;
    PCSA_CALLSTACK_INTERNAL callstackInternal = NULL;
    PCSA_CALLSTACK callstack = NULL;
    PEPROCESS process = NULL;
    NTSTATUS status;
    LONGLONG processCreateTime;

    PAGED_CODE();

    if (Analyzer == NULL || !Analyzer->Initialized || Callstack == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ProcessId == NULL || ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Callstack = NULL;

    analyzerInternal = CONTAINING_RECORD(Analyzer, CSA_ANALYZER_INTERNAL, Public);

    if (analyzerInternal->ShuttingDown) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    //
    // Throttle check — prevent DoS via excessive captures
    //
    if (!CsapThrottleCheck(analyzerInternal)) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Take an operational reference. This prevents the analyzer from being
    // freed while this capture is in progress.
    //
    CsapReferenceAnalyzer(analyzerInternal);

    //
    // Get process create time for PID-reuse protection
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        CsapDereferenceAnalyzer(analyzerInternal);
        return status;
    }
    processCreateTime = PsGetProcessCreateTimeQuadPart(process);

    callstackInternal = (PCSA_CALLSTACK_INTERNAL)ExAllocateFromNPagedLookasideList(
        &analyzerInternal->CallstackLookaside
        );

    if (callstackInternal == NULL) {
        ObDereferenceObject(process);
        CsapDereferenceAnalyzer(analyzerInternal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(callstackInternal, sizeof(CSA_CALLSTACK_INTERNAL));

    callstackInternal->Signature = CSA_CALLSTACK_SIGNATURE;
    callstackInternal->AnalyzerRef = analyzerInternal;

    callstack = &callstackInternal->Callstack;
    callstack->ProcessId = ProcessId;
    callstack->ThreadId = ThreadId;
    callstack->FrameCount = 0;
    callstack->AggregatedAnomalies = CsaAnomaly_None;
    callstack->SuspicionScore = 0;
    callstack->IsWow64Process = ShadowStrikeIsProcessWow64(process);

    KeQuerySystemTimePrecise(&callstack->CaptureTime);

    //
    // Ensure module cache is populated for this process
    //
    (VOID)CsapPopulateModuleCache(analyzerInternal, ProcessId, processCreateTime);

    ObDereferenceObject(process);
    process = NULL;

    //
    // Capture user-mode stack
    //
    status = CsapCaptureUserStack(analyzerInternal, ProcessId, ThreadId, callstack);
    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&analyzerInternal->CallstackLookaside, callstackInternal);
        CsapDereferenceAnalyzer(analyzerInternal);
        return status;
    }

    //
    // Analyze all frames in a single pass (batched attach)
    //
    status = CsapAnalyzeFrames(analyzerInternal, ProcessId, callstack);
    if (!NT_SUCCESS(status)) {
        //
        // Analysis failure is non-fatal; we still return the captured stack.
        //
    }

    callstack->SuspicionScore = CsapCalculateSuspicionScore(callstack);

    InterlockedIncrement64(&Analyzer->Stats.StacksCaptured);

    if (callstack->AggregatedAnomalies != CsaAnomaly_None) {
        InterlockedIncrement64(&Analyzer->Stats.AnomaliesFound);
    }

    //
    // Note: We do NOT release the analyzer ref here. The ref is held until
    // CsaFreeCallstack is called, ensuring the lookaside list is valid for
    // the lifetime of the callstack object.
    //

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

        if (!frame->IsBackedByImage) {
            valid = FALSE;
            break;
        }

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
{
    NTSTATUS status;
    PETHREAD thread = NULL;
    PEPROCESS process = NULL;
    HANDLE processId;
    BOOLEAN pivoted = FALSE;
    PVOID capturedFrames[16];
    ULONG capturedCount;
    KAPC_STATE apcState;

    if (Analyzer == NULL || !Analyzer->Initialized ||
        ThreadId == NULL || IsPivoted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsPivoted = FALSE;

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    processId = PsGetThreadProcessId(thread);

    status = PsLookupProcessByProcessId(processId, &process);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        ObDereferenceObject(thread);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    //
    // Walk up to 16 user-mode frames. RtlWalkFrameChain with flag=1
    // traverses user-mode frames only.
    //
    capturedCount = 0;
    RtlZeroMemory(capturedFrames, sizeof(capturedFrames));

    KeStackAttachProcess(process, &apcState);

    __try {
        capturedCount = RtlWalkFrameChain(capturedFrames, 16, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Stack walk threw an exception — the stack is corrupted or pivoted
        // to an unmapped region. Strong indicator.
        //
        pivoted = TRUE;
    }

    KeUnstackDetachProcess(&apcState);

    if (pivoted) {
        *IsPivoted = TRUE;
        ObDereferenceObject(process);
        ObDereferenceObject(thread);
        return STATUS_SUCCESS;
    }

    if (capturedCount == 0) {
        //
        // Zero frames could mean the thread is at its entry point or
        // in kernel-only context. Not conclusive on its own.
        //
        ObDereferenceObject(process);
        ObDereferenceObject(thread);
        return STATUS_SUCCESS;
    }

    //
    // Heuristic 1: All captured return addresses must be in valid user range.
    //
    {
        ULONG invalidCount = 0;
        for (ULONG i = 0; i < capturedCount; i++) {
            ULONG_PTR addr = (ULONG_PTR)capturedFrames[i];
            if (addr < CSA_MIN_VALID_USER_ADDRESS || addr > CSA_MAX_USER_ADDRESS) {
                invalidCount++;
            }
        }

        if (invalidCount == capturedCount) {
            pivoted = TRUE;
        }
    }

    //
    // Heuristic 2: Verify CALL instruction precedes each return address.
    // In a legitimate stack, every return address is placed by a CALL.
    // In a ROP chain / pivoted stack, "return addresses" are arbitrary.
    // We check up to 8 frames for:
    //   - E8 xx xx xx xx  (call rel32) at [addr-5]
    //   - FF 15 xx xx xx xx (call [rip+disp32]) at [addr-6]
    //   - FF D0..D7 (call reg) at [addr-2]
    //
    if (!pivoted && capturedCount > 0) {
        ULONG noCallCount = 0;
        ULONG checkedFrames = 0;

        KeStackAttachProcess(process, &apcState);

        __try {
            for (ULONG i = 0; i < capturedCount && i < 8; i++) {
                ULONG_PTR addr = (ULONG_PTR)capturedFrames[i];
                if (addr < CSA_MIN_VALID_USER_ADDRESS + 7 ||
                    addr > CSA_MAX_USER_ADDRESS) {
                    continue;
                }

                UCHAR buf[7];
                PVOID readAddr = (PVOID)(addr - 7);

                ProbeForRead(readAddr, 7, 1);
                RtlCopyMemory(buf, readAddr, 7);

                BOOLEAN foundCall = FALSE;

                // call rel32: E8 at [addr-5] → buf[2]
                if (buf[2] == 0xE8) {
                    foundCall = TRUE;
                }

                // call [rip+disp32]: FF 15 at [addr-6] → buf[1..2]
                if (!foundCall && buf[1] == 0xFF && buf[2] == 0x15) {
                    foundCall = TRUE;
                }

                // call reg: FF D0..D7 at [addr-2] → buf[5..6]
                if (!foundCall && buf[5] == 0xFF &&
                    buf[6] >= 0xD0 && buf[6] <= 0xD7) {
                    foundCall = TRUE;
                }

                // call [reg]: FF 10..17 at [addr-2] → buf[5..6]
                if (!foundCall && buf[5] == 0xFF &&
                    buf[6] >= 0x10 && buf[6] <= 0x17) {
                    foundCall = TRUE;
                }

                checkedFrames++;
                if (!foundCall) {
                    noCallCount++;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            //
            // Exception reading code near return addresses — suspicious
            // but not conclusive by itself.
            //
        }

        KeUnstackDetachProcess(&apcState);

        //
        // If 2/3+ of checked frames have no preceding CALL instruction,
        // the stack is very likely pivoted or ROP-chained.
        //
        if (checkedFrames >= 3 && noCallCount >= ((checkedFrames * 2) / 3)) {
            pivoted = TRUE;
        }
    }

    ObDereferenceObject(process);
    ObDereferenceObject(thread);

    *IsPivoted = pivoted;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
CsaFreeCallstack(
    _In_ PCSA_CALLSTACK Callstack
    )
{
    PCSA_CALLSTACK_INTERNAL callstackInternal;

    PAGED_CODE();

    if (Callstack == NULL) {
        return;
    }

    callstackInternal = CONTAINING_RECORD(Callstack, CSA_CALLSTACK_INTERNAL, Callstack);

    if (callstackInternal->Signature != CSA_CALLSTACK_SIGNATURE) {
        return;
    }

    callstackInternal->Signature = 0;

    if (callstackInternal->AnalyzerRef != NULL) {
        PCSA_ANALYZER_INTERNAL analyzerRef = callstackInternal->AnalyzerRef;
        callstackInternal->AnalyzerRef = NULL;

        //
        // Return to lookaside. Safe because we hold an analyzer ref that
        // prevents the lookaside from being deleted.
        //
        ExFreeToNPagedLookasideList(
            &analyzerRef->CallstackLookaside,
            callstackInternal
            );

        //
        // Release the operational reference taken in CsaCaptureCallstack.
        //
        CsapDereferenceAnalyzer(analyzerRef);
    }
}


_Use_decl_annotations_
VOID
CsaOnProcessExit(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId
    )
{
    PCSA_ANALYZER_INTERNAL analyzerInternal;

    PAGED_CODE();

    if (Analyzer == NULL || !Analyzer->Initialized) {
        return;
    }

    analyzerInternal = CONTAINING_RECORD(Analyzer, CSA_ANALYZER_INTERNAL, Public);

    if (analyzerInternal->ShuttingDown) {
        return;
    }

    CsapEvictProcessEntries(analyzerInternal, ProcessId);
}


//=============================================================================
// Internal Functions — Throttle
//=============================================================================

static
BOOLEAN
CsapThrottleCheck(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal
    )
{
    LARGE_INTEGER now;
    LONGLONG windowStart;
    LONG count;

    KeQuerySystemTimePrecise(&now);
    windowStart = InterlockedCompareExchange64(
        &AnalyzerInternal->CaptureWindowStart,
        0, 0
        );

    if ((now.QuadPart - windowStart) > CSA_THROTTLE_WINDOW_100NS) {
        //
        // Window expired — reset
        //
        InterlockedExchange64(&AnalyzerInternal->CaptureWindowStart, now.QuadPart);
        InterlockedExchange(&AnalyzerInternal->CapturesInWindow, 1);
        return TRUE;
    }

    count = InterlockedIncrement(&AnalyzerInternal->CapturesInWindow);
    return (count <= CSA_MAX_CAPTURES_PER_SECOND);
}


//=============================================================================
// Internal Functions — Stack Capture
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
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PVOID rawFrames[CSA_MAX_FRAMES];
    ULONG capturedCount = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(AnalyzerInternal);
    UNREFERENCED_PARAMETER(ThreadId);

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    RtlZeroMemory(rawFrames, sizeof(rawFrames));

    //
    // Attach and capture using RtlWalkFrameChain with flag=1 for user-mode.
    // This properly uses unwind data (.pdata / RUNTIME_FUNCTION) on x64,
    // unlike manual frame-pointer walking which is unreliable.
    //
    KeStackAttachProcess(process, &apcState);

    __try {
        capturedCount = RtlWalkFrameChain(rawFrames, CSA_MAX_FRAMES, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        capturedCount = 0;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    //
    // Populate frame structures from captured raw return addresses
    //
    for (i = 0; i < capturedCount && i < CSA_MAX_FRAMES; i++) {
        ULONG_PTR addr = (ULONG_PTR)rawFrames[i];

        if (addr < CSA_MIN_VALID_USER_ADDRESS || addr > CSA_MAX_USER_ADDRESS) {
            break;
        }

        Callstack->Frames[i].ReturnAddress = rawFrames[i];
        Callstack->Frames[i].FramePointer = NULL;
        Callstack->Frames[i].StackPointer = NULL;
        Callstack->Frames[i].Type = CsaFrame_User;
        Callstack->Frames[i].AnomalyFlags = CsaAnomaly_None;
        Callstack->Frames[i].IsWow64Frame = Callstack->IsWow64Process;
        Callstack->FrameCount = i + 1;
    }

    if (Callstack->FrameCount < CSA_MIN_STACK_FRAMES) {
        Callstack->AggregatedAnomalies |= CsaAnomaly_MissingFrames;
    }

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal Functions — Frame Analysis (batched single-attach)
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
CsapAnalyzeFrames(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _Inout_ PCSA_CALLSTACK Callstack
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PCSA_MODULE_CACHE_ENTRY moduleEntry = NULL;
    LONGLONG processCreateTime;
    ULONG i;

    //
    // Single process attach for all frame analysis reads
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    processCreateTime = PsGetProcessCreateTimeQuadPart(process);

    for (i = 0; i < Callstack->FrameCount; i++) {
        PCSA_STACK_FRAME frame = &Callstack->Frames[i];
        ULONG protection = 0;
        BOOLEAN isBacked = FALSE;

        moduleEntry = NULL;

        status = CsapLookupModule(
            AnalyzerInternal,
            ProcessId,
            processCreateTime,
            frame->ReturnAddress,
            &moduleEntry
            );

        if (NT_SUCCESS(status) && moduleEntry != NULL) {
            frame->ModuleBase = moduleEntry->ModuleBase;
            frame->OffsetInModule = (ULONG64)((ULONG_PTR)frame->ReturnAddress -
                                              (ULONG_PTR)moduleEntry->ModuleBase);
            frame->IsBackedByImage = TRUE;

            //
            // Deep-copy module name
            //
            USHORT copyLen = min(
                moduleEntry->ModuleName.Length,
                (USHORT)(sizeof(frame->ModuleNameBuffer) - sizeof(WCHAR))
                );
            RtlCopyMemory(frame->ModuleNameBuffer, moduleEntry->ModuleName.Buffer, copyLen);
            frame->ModuleNameBuffer[copyLen / sizeof(WCHAR)] = L'\0';
            RtlInitUnicodeString(&frame->ModuleName, frame->ModuleNameBuffer);

            if (moduleEntry->IsNtdll) {
                frame->Type = CsaFrame_SystemCall;
            }

            if (!CsapIsReturnAddressValid(frame->ReturnAddress, moduleEntry)) {
                frame->AnomalyFlags |= CsaAnomaly_SpoofedFrames;
            }

            CsapDereferenceModuleEntry(moduleEntry);
        } else {
            //
            // No module found — unbacked code
            //
            frame->ModuleBase = NULL;
            RtlZeroMemory(&frame->ModuleName, sizeof(UNICODE_STRING));
            frame->OffsetInModule = 0;
            frame->IsBackedByImage = FALSE;
            frame->AnomalyFlags |= CsaAnomaly_UnbackedCode | CsaAnomaly_UnknownModule;

            status = CsapGetMemoryProtection(ProcessId, frame->ReturnAddress, &protection, &isBacked);
            if (NT_SUCCESS(status)) {
                frame->MemoryProtection = protection;

                if ((protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                    frame->AnomalyFlags |= CsaAnomaly_RWXMemory;
                }
            }

            //
            // Single-attach analysis of unbacked code: ROP gadgets + direct syscall
            //
            CSA_ANOMALY codeAnomalies = CsapAnalyzeUnbackedCode(process, frame->ReturnAddress);
            frame->AnomalyFlags |= codeAnomalies;
        }

        Callstack->AggregatedAnomalies |= frame->AnomalyFlags;
    }

    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal Functions — Module Cache
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
CsapLookupModule(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ LONGLONG ProcessCreateTime,
    _In_ PVOID Address,
    _Out_ PCSA_MODULE_CACHE_ENTRY* ModuleEntry
    )
{
    PLIST_ENTRY entry;
    PCSA_MODULE_CACHE_ENTRY cacheEntry;

    *ModuleEntry = NULL;

    //
    // Linear scan of the module list. This is correct for range-based lookups
    // where hashing by address is fundamentally broken (an arbitrary address
    // within a module hashes differently than the module base).
    // With CSA_MAX_CACHED_MODULES=512 this is bounded and fast enough.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&AnalyzerInternal->Public.ModuleLock);

    for (entry = AnalyzerInternal->Public.ModuleCache.Flink;
         entry != &AnalyzerInternal->Public.ModuleCache;
         entry = entry->Flink) {

        cacheEntry = CONTAINING_RECORD(entry, CSA_MODULE_CACHE_ENTRY, ListEntry);

        if (cacheEntry->ProcessId != ProcessId) {
            continue;
        }

        //
        // PID-reuse protection: reject stale entries from old processes
        //
        if (cacheEntry->ProcessCreateTime != ProcessCreateTime) {
            continue;
        }

        if ((ULONG_PTR)Address >= (ULONG_PTR)cacheEntry->ModuleBase &&
            ((ULONG_PTR)Address - (ULONG_PTR)cacheEntry->ModuleBase) < cacheEntry->ModuleSize) {

            CsapReferenceModuleEntry(cacheEntry);

            ExReleasePushLockShared(&AnalyzerInternal->Public.ModuleLock);
            KeLeaveCriticalRegion();

            *ModuleEntry = cacheEntry;
            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockShared(&AnalyzerInternal->Public.ModuleLock);
    KeLeaveCriticalRegion();

    return STATUS_NOT_FOUND;
}


static
_Use_decl_annotations_
NTSTATUS
CsapPopulateModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId,
    _In_ LONGLONG ProcessCreateTime
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PKM_PEB peb = NULL;
    KAPC_STATE apcState;
    ULONG snapshotCount = 0;
    ULONG i;

    //
    // Phase 1: Attach and snapshot module data into kernel-side buffers.
    // NO locks are held during this phase.
    //
    PCSA_MODULE_SNAPSHOT_ENTRY snapshot = NULL;
    SIZE_T snapshotSize = CSA_MAX_MODULES_PER_POPULATE * sizeof(CSA_MODULE_SNAPSHOT_ENTRY);

    snapshot = (PCSA_MODULE_SNAPSHOT_ENTRY)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        snapshotSize,
        CSA_POOL_TAG
        );

    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(snapshot, snapshotSize);

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(snapshot, CSA_POOL_TAG);
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        ShadowStrikeFreePoolWithTag(snapshot, CSA_POOL_TAG);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    peb = (PKM_PEB)PsGetProcessPeb(process);
    if (peb == NULL) {
        ObDereferenceObject(process);
        ShadowStrikeFreePoolWithTag(snapshot, CSA_POOL_TAG);
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        //
        // Validate PEB is in user-mode address range
        //
        if ((ULONG_PTR)peb < CSA_MIN_VALID_USER_ADDRESS ||
            (ULONG_PTR)peb > CSA_MAX_USER_ADDRESS) {
            status = STATUS_INVALID_ADDRESS;
            __leave;
        }

        ProbeForRead(peb, KM_PEB_PROBE_SIZE, sizeof(PVOID));

        PKM_PEB_LDR_DATA ldrData = peb->Ldr;
        if (ldrData == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        if ((ULONG_PTR)ldrData < CSA_MIN_VALID_USER_ADDRESS ||
            (ULONG_PTR)ldrData > CSA_MAX_USER_ADDRESS) {
            status = STATUS_INVALID_ADDRESS;
            __leave;
        }

        ProbeForRead(ldrData, KM_PEB_LDR_PROBE_SIZE, sizeof(PVOID));

        PLIST_ENTRY listHead = &ldrData->InMemoryOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;

        while (listEntry != listHead &&
               snapshotCount < CSA_MAX_MODULES_PER_POPULATE) {

            if ((ULONG_PTR)listEntry < CSA_MIN_VALID_USER_ADDRESS ||
                (ULONG_PTR)listEntry > CSA_MAX_USER_ADDRESS) {
                break;
            }

            PKM_LDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(
                listEntry,
                KM_LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
                );

            if ((ULONG_PTR)ldrEntry < CSA_MIN_VALID_USER_ADDRESS ||
                (ULONG_PTR)ldrEntry > CSA_MAX_USER_ADDRESS) {
                break;
            }

            ProbeForRead(ldrEntry, KM_LDR_ENTRY_PROBE_SIZE, sizeof(PVOID));

            PVOID dllBase = ldrEntry->DllBase;
            SIZE_T sizeOfImage = ldrEntry->SizeOfImage;

            //
            // Validate module base is in user space and size is sane
            //
            if (dllBase == NULL ||
                (ULONG_PTR)dllBase < CSA_MIN_VALID_USER_ADDRESS ||
                (ULONG_PTR)dllBase > CSA_MAX_USER_ADDRESS ||
                sizeOfImage == 0 ||
                sizeOfImage > CSA_MAX_MODULE_SIZE ||
                ((ULONG_PTR)dllBase + sizeOfImage) < (ULONG_PTR)dllBase) {
                listEntry = listEntry->Flink;
                continue;
            }

            snapshot[snapshotCount].DllBase = dllBase;
            snapshot[snapshotCount].SizeOfImage = sizeOfImage;
            snapshot[snapshotCount].Valid = TRUE;

            //
            // Copy module name
            //
            if (ldrEntry->BaseDllName.Buffer != NULL &&
                ldrEntry->BaseDllName.Length > 0 &&
                (ULONG_PTR)ldrEntry->BaseDllName.Buffer >= CSA_MIN_VALID_USER_ADDRESS &&
                (ULONG_PTR)ldrEntry->BaseDllName.Buffer <= CSA_MAX_USER_ADDRESS) {

                USHORT nameLen = min(
                    ldrEntry->BaseDllName.Length,
                    (USHORT)(sizeof(snapshot[snapshotCount].BaseDllName) - sizeof(WCHAR))
                    );

                ProbeForRead(ldrEntry->BaseDllName.Buffer, nameLen, sizeof(WCHAR));
                RtlCopyMemory(snapshot[snapshotCount].BaseDllName,
                              ldrEntry->BaseDllName.Buffer,
                              nameLen);
                snapshot[snapshotCount].BaseDllName[nameLen / sizeof(WCHAR)] = L'\0';
                snapshot[snapshotCount].NameLength = nameLen;
            }

            snapshotCount++;
            listEntry = listEntry->Flink;
        }

        status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    //
    // Phase 2: Process the snapshot under lock — no user-mode access here.
    // This eliminates the lock-inside-__try bug entirely.
    //
    if (NT_SUCCESS(status) || snapshotCount > 0) {
        for (i = 0; i < snapshotCount; i++) {
            if (!snapshot[i].Valid) {
                continue;
            }

            //
            // Check if already cached
            //
            PCSA_MODULE_CACHE_ENTRY existing = NULL;
            NTSTATUS lookupStatus = CsapLookupModule(
                AnalyzerInternal,
                ProcessId,
                ProcessCreateTime,
                snapshot[i].DllBase,
                &existing
                );

            if (NT_SUCCESS(lookupStatus) && existing != NULL) {
                CsapDereferenceModuleEntry(existing);
                continue;
            }

            //
            // Allocate and populate cache entry
            //
            PCSA_MODULE_CACHE_ENTRY cacheEntry =
                (PCSA_MODULE_CACHE_ENTRY)ExAllocateFromNPagedLookasideList(
                    &AnalyzerInternal->ModuleCacheLookaside
                    );

            if (cacheEntry == NULL) {
                continue;
            }

            RtlZeroMemory(cacheEntry, sizeof(CSA_MODULE_CACHE_ENTRY));

            cacheEntry->Signature = CSA_MODULE_SIGNATURE;
            cacheEntry->RefCount = 1;
            cacheEntry->ProcessId = ProcessId;
            cacheEntry->ProcessCreateTime = ProcessCreateTime;
            cacheEntry->ModuleBase = snapshot[i].DllBase;
            cacheEntry->ModuleSize = snapshot[i].SizeOfImage;

            if (snapshot[i].NameLength > 0) {
                USHORT copyLen = min(
                    snapshot[i].NameLength,
                    (USHORT)(sizeof(cacheEntry->ModuleNameBuffer) - sizeof(WCHAR))
                    );
                RtlCopyMemory(cacheEntry->ModuleNameBuffer,
                              snapshot[i].BaseDllName,
                              copyLen);
                cacheEntry->ModuleNameBuffer[copyLen / sizeof(WCHAR)] = L'\0';
                RtlInitUnicodeString(&cacheEntry->ModuleName, cacheEntry->ModuleNameBuffer);

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

            //
            // Populate .text section info while attached to process
            //
            CsapPopulateTextSection(process, cacheEntry);

            //
            // Insert under exclusive lock — no user-mode access here
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&AnalyzerInternal->Public.ModuleLock);

            InsertTailList(&AnalyzerInternal->Public.ModuleCache, &cacheEntry->ListEntry);
            InterlockedIncrement(&AnalyzerInternal->CachedModuleCount);

            ExReleasePushLockExclusive(&AnalyzerInternal->Public.ModuleLock);
            KeLeaveCriticalRegion();
        }
    }

    ObDereferenceObject(process);
    ShadowStrikeFreePoolWithTag(snapshot, CSA_POOL_TAG);

    return status;
}


//=============================================================================
// Internal Functions — .text Section Population
//=============================================================================

static
VOID
CsapPopulateTextSection(
    _In_ PEPROCESS Process,
    _Inout_ PCSA_MODULE_CACHE_ENTRY CacheEntry
    )
{
    KAPC_STATE apcState;

    if (CacheEntry->ModuleBase == NULL) {
        return;
    }

    KeStackAttachProcess(Process, &apcState);

    __try {
        PUCHAR base = (PUCHAR)CacheEntry->ModuleBase;

        if ((ULONG_PTR)base < CSA_MIN_VALID_USER_ADDRESS ||
            (ULONG_PTR)base > CSA_MAX_USER_ADDRESS) {
            __leave;
        }

        ProbeForRead(base, sizeof(IMAGE_DOS_HEADER), sizeof(USHORT));

        PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)base;
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
            __leave;
        }

        LONG peOffset = dosHdr->e_lfanew;
        if (peOffset < 0 || peOffset > 1024) {
            __leave;
        }

        PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(base + peOffset);

        if ((ULONG_PTR)ntHdr < CSA_MIN_VALID_USER_ADDRESS ||
            (ULONG_PTR)ntHdr > CSA_MAX_USER_ADDRESS) {
            __leave;
        }

        ProbeForRead(ntHdr, sizeof(IMAGE_NT_HEADERS), sizeof(ULONG));

        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
            __leave;
        }

        ULONG numberOfSections = ntHdr->FileHeader.NumberOfSections;
        if (numberOfSections == 0 || numberOfSections > 96) {
            __leave;
        }

        PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(ntHdr);

        if ((ULONG_PTR)sectionHdr < CSA_MIN_VALID_USER_ADDRESS ||
            (ULONG_PTR)sectionHdr > CSA_MAX_USER_ADDRESS) {
            __leave;
        }

        ProbeForRead(sectionHdr,
                     numberOfSections * sizeof(IMAGE_SECTION_HEADER),
                     sizeof(ULONG));

        for (ULONG s = 0; s < numberOfSections; s++) {
            if ((sectionHdr[s].Characteristics & IMAGE_SCN_CNT_CODE) &&
                (sectionHdr[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

                CacheEntry->TextSectionBase = base + sectionHdr[s].VirtualAddress;
                CacheEntry->TextSectionSize = sectionHdr[s].Misc.VirtualSize;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // PE parsing failed — leave TextSection fields as NULL/0
    }

    KeUnstackDetachProcess(&apcState);
}


//=============================================================================
// Internal Functions — Module Cache Reference Counting
//=============================================================================

static
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
VOID
CsapDereferenceModuleEntry(
    _Inout_ PCSA_MODULE_CACHE_ENTRY Entry
    )
{
    if (Entry == NULL) {
        return;
    }

    InterlockedDecrement(&Entry->RefCount);

    //
    // Entries are freed during cache eviction or cleanup, not inline.
    // The eviction path checks RefCount before freeing.
    //
}


//=============================================================================
// Internal Functions — Module Cache Cleanup
//=============================================================================

static
_Use_decl_annotations_
VOID
CsapCleanupModuleCache(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal
    )
{
    PLIST_ENTRY entry;
    PCSA_MODULE_CACHE_ENTRY cacheEntry;
    LIST_ENTRY entriesToFree;

    PAGED_CODE();

    InitializeListHead(&entriesToFree);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&AnalyzerInternal->Public.ModuleLock);

    while (!IsListEmpty(&AnalyzerInternal->Public.ModuleCache)) {
        entry = RemoveHeadList(&AnalyzerInternal->Public.ModuleCache);
        cacheEntry = CONTAINING_RECORD(entry, CSA_MODULE_CACHE_ENTRY, ListEntry);

        InsertTailList(&entriesToFree, entry);
    }

    AnalyzerInternal->CachedModuleCount = 0;

    ExReleasePushLockExclusive(&AnalyzerInternal->Public.ModuleLock);
    KeLeaveCriticalRegion();

    //
    // Free entries outside the lock. During shutdown, all operational
    // references have been drained, so RefCount should be 1 (the initial
    // reference). We free regardless — this is only called during shutdown.
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


static
_Use_decl_annotations_
VOID
CsapEvictProcessEntries(
    _In_ PCSA_ANALYZER_INTERNAL AnalyzerInternal,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PCSA_MODULE_CACHE_ENTRY cacheEntry;
    LIST_ENTRY entriesToFree;

    InitializeListHead(&entriesToFree);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&AnalyzerInternal->Public.ModuleLock);

    for (entry = AnalyzerInternal->Public.ModuleCache.Flink;
         entry != &AnalyzerInternal->Public.ModuleCache;
         entry = next) {

        next = entry->Flink;
        cacheEntry = CONTAINING_RECORD(entry, CSA_MODULE_CACHE_ENTRY, ListEntry);

        if (cacheEntry->ProcessId == ProcessId) {
            //
            // Only evict if no outstanding references (RefCount == 1 means
            // only the cache itself holds a ref). If RefCount > 1, a lookup
            // is in progress; the entry will be evicted on the next pass or
            // at shutdown.
            //
            if (cacheEntry->RefCount <= 1) {
                RemoveEntryList(entry);
                InterlockedDecrement(&AnalyzerInternal->CachedModuleCount);
                InsertTailList(&entriesToFree, entry);
            }
        }
    }

    ExReleasePushLockExclusive(&AnalyzerInternal->Public.ModuleLock);
    KeLeaveCriticalRegion();

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
// Internal Functions — Memory Analysis
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
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    PVOID tebRaw = NULL;
    PNT_TIB tib = NULL;
    KAPC_STATE apcState;

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

    tebRaw = PsGetThreadTeb(thread);
    if (tebRaw == NULL) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    //
    // Validate TEB is in user-mode range
    //
    if ((ULONG_PTR)tebRaw < CSA_MIN_VALID_USER_ADDRESS ||
        (ULONG_PTR)tebRaw > CSA_MAX_USER_ADDRESS) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_INVALID_ADDRESS;
    }

    tib = (PNT_TIB)tebRaw;

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(tib, sizeof(NT_TIB), sizeof(PVOID));

        PVOID base = tib->StackBase;
        PVOID limit = tib->StackLimit;

        //
        // Validate stack bounds are in user space and ordered correctly
        //
        if ((ULONG_PTR)base > CSA_MAX_USER_ADDRESS ||
            (ULONG_PTR)limit < CSA_MIN_VALID_USER_ADDRESS ||
            (ULONG_PTR)limit >= (ULONG_PTR)base) {
            status = STATUS_INVALID_ADDRESS;
        } else {
            *StackBase = base;
            *StackLimit = limit;
            status = STATUS_SUCCESS;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    ObDereferenceObject(thread);
    ObDereferenceObject(process);

    return status;
}


//=============================================================================
// Internal Functions — Return Address Validation
//=============================================================================

static
_Use_decl_annotations_
BOOLEAN
CsapIsReturnAddressValid(
    _In_ PVOID ReturnAddress,
    _In_ PCSA_MODULE_CACHE_ENTRY Module
    )
{
    ULONG_PTR offset;

    if (Module == NULL) {
        return FALSE;
    }

    if ((ULONG_PTR)ReturnAddress < (ULONG_PTR)Module->ModuleBase ||
        ((ULONG_PTR)ReturnAddress - (ULONG_PTR)Module->ModuleBase) >= Module->ModuleSize) {
        return FALSE;
    }

    offset = (ULONG_PTR)ReturnAddress - (ULONG_PTR)Module->ModuleBase;

    //
    // If .text section info was populated, validate the return address
    // points into executable code, not data sections.
    //
    if (Module->TextSectionBase != NULL && Module->TextSectionSize > 0) {
        ULONG_PTR textStart = (ULONG_PTR)Module->TextSectionBase -
                              (ULONG_PTR)Module->ModuleBase;

        if (offset < textStart || (offset - textStart) >= Module->TextSectionSize) {
            return FALSE;
        }
    }

    return TRUE;
}


//=============================================================================
// Internal Functions — ROP Gadget Detection
//=============================================================================

static
_Use_decl_annotations_
CSA_ANOMALY
CsapAnalyzeUnbackedCode(
    _In_ PEPROCESS Process,
    _In_ PVOID Address
    )
/*++
Routine Description:
    Performs comprehensive analysis of an unbacked return address in a single
    process attach. Detects ROP gadget patterns, direct syscall instructions,
    and other suspicious code sequences. Returns a bitmask of anomaly flags.

    This replaces the old separate CsapDetectRopGadget + inline direct syscall
    check, eliminating redundant KeStackAttachProcess calls per frame.

Arguments:
    Process - Target process (already referenced by caller).
    Address - Return address to analyze.

Return Value:
    Bitmask of CSA_ANOMALY flags detected at this address.
--*/
{
    KAPC_STATE apcState;
    CSA_ANOMALY result = CsaAnomaly_None;
    UCHAR codeBuffer[CSA_ROP_GADGET_WINDOW + 2];
    ULONG totalInstructions;

    if ((ULONG_PTR)Address < CSA_MIN_VALID_USER_ADDRESS + CSA_ROP_GADGET_WINDOW ||
        (ULONG_PTR)Address > CSA_MAX_USER_ADDRESS) {
        return CsaAnomaly_None;
    }

    KeStackAttachProcess(Process, &apcState);

    __try {
        PVOID readAddr = (PVOID)((ULONG_PTR)Address - CSA_ROP_GADGET_WINDOW);

        ProbeForRead(readAddr, CSA_ROP_GADGET_WINDOW + 2, 1);
        RtlCopyMemory(codeBuffer, readAddr, CSA_ROP_GADGET_WINDOW + 2);

        //
        // === Direct syscall / sysenter detection ===
        // If the 2 bytes immediately before the return address are
        // syscall (0F 05) or sysenter (0F 34), this is a direct system call
        // from unbacked memory — extremely suspicious.
        //
        UCHAR b0 = codeBuffer[CSA_ROP_GADGET_WINDOW - 2];  // [Address - 2]
        UCHAR b1 = codeBuffer[CSA_ROP_GADGET_WINDOW - 1];  // [Address - 1]

        if ((b0 == 0x0F && b1 == 0x05) ||   // syscall
            (b0 == 0x0F && b1 == 0x34)) {    // sysenter
            result |= CsaAnomaly_DirectSyscall;
        }

        //
        // === ROP gadget detection ===
        // A ROP gadget is a short instruction sequence ending in a control
        // transfer that an attacker chains together. We check for multiple
        // gadget terminator patterns and measure how short the preceding
        // code is (shorter = more likely a gadget, not a real function).
        //
        UCHAR prevByte  = codeBuffer[CSA_ROP_GADGET_WINDOW - 1];  // [Address - 1]
        UCHAR prev2Byte = codeBuffer[CSA_ROP_GADGET_WINDOW - 2];  // [Address - 2]

        //
        // Pattern 1: ret (C3) at [Address - 1]
        // ROP chain terminators. Check if the code before it is gadget-short.
        //
        if (prevByte == CSA_RET_OPCODE) {
            totalInstructions = 0;
            for (int k = CSA_ROP_GADGET_WINDOW - 2; k >= 0; k--) {
                totalInstructions++;
                if (codeBuffer[k] == CSA_RET_OPCODE ||
                    codeBuffer[k] == 0xCC) {   // int3 (padding / boundary)
                    break;
                }
            }
            if (totalInstructions <= 4) {
                result |= CsaAnomaly_ReturnGadget;
            }
        }

        //
        // Pattern 2: ret imm16 (C2 xx xx) at [Address - 3]
        // Used in gadgets that need to clean up stack arguments.
        //
        if (!(result & CsaAnomaly_ReturnGadget) && CSA_ROP_GADGET_WINDOW >= 3) {
            if (codeBuffer[CSA_ROP_GADGET_WINDOW - 3] == CSA_RET_IMM16_OPCODE) {
                USHORT immVal = *(PUSHORT)(&codeBuffer[CSA_ROP_GADGET_WINDOW - 2]);
                if (immVal <= 0x40) {
                    result |= CsaAnomaly_ReturnGadget;
                }
            }
        }

        //
        // Pattern 3: jmp reg (FF E0..E7) at [Address - 2]
        // JOP (Jump-Oriented Programming) gadgets.
        // FF E0 = jmp rax, FF E1 = jmp rcx, ..., FF E7 = jmp rdi
        //
        if (!(result & CsaAnomaly_ReturnGadget)) {
            if (prev2Byte == 0xFF && (prevByte >= 0xE0 && prevByte <= 0xE7)) {
                totalInstructions = 0;
                for (int k = CSA_ROP_GADGET_WINDOW - 3; k >= 0; k--) {
                    totalInstructions++;
                    if (codeBuffer[k] == CSA_RET_OPCODE ||
                        codeBuffer[k] == 0xCC) {
                        break;
                    }
                }
                if (totalInstructions <= 4) {
                    result |= CsaAnomaly_ReturnGadget;
                }
            }
        }

        //
        // Pattern 4: call reg (FF D0..D7) at [Address - 2]
        // COP (Call-Oriented Programming) gadgets.
        // FF D0 = call rax, FF D1 = call rcx, ..., FF D7 = call rdi
        //
        if (!(result & CsaAnomaly_ReturnGadget)) {
            if (prev2Byte == 0xFF && (prevByte >= 0xD0 && prevByte <= 0xD7)) {
                totalInstructions = 0;
                for (int k = CSA_ROP_GADGET_WINDOW - 3; k >= 0; k--) {
                    totalInstructions++;
                    if (codeBuffer[k] == CSA_RET_OPCODE ||
                        codeBuffer[k] == 0xCC) {
                        break;
                    }
                }
                if (totalInstructions <= 3) {
                    result |= CsaAnomaly_ReturnGadget;
                }
            }
        }

        //
        // Pattern 5: jmp [reg] / jmp [reg+disp8] (FF 20..27 / FF 60..67)
        // Indirect jump gadgets used in vtable-based JOP chains.
        //
        if (!(result & CsaAnomaly_ReturnGadget)) {
            if (prev2Byte == 0xFF &&
                ((prevByte >= 0x20 && prevByte <= 0x27) ||
                 (prevByte >= 0x60 && prevByte <= 0x67))) {
                result |= CsaAnomaly_ReturnGadget;
            }
        }

        //
        // Pattern 6: syscall (0F 05) or sysenter (0F 34) as gadget terminator
        // Attackers chain to a syscall gadget to invoke kernel services directly.
        //
        if (!(result & CsaAnomaly_ReturnGadget)) {
            if ((prev2Byte == 0x0F && prevByte == 0x05) ||
                (prev2Byte == 0x0F && prevByte == 0x34)) {
                totalInstructions = 0;
                for (int k = CSA_ROP_GADGET_WINDOW - 3; k >= 0; k--) {
                    totalInstructions++;
                    if (codeBuffer[k] == CSA_RET_OPCODE ||
                        codeBuffer[k] == 0xCC) {
                        break;
                    }
                }
                if (totalInstructions <= 4) {
                    result |= CsaAnomaly_ReturnGadget;
                }
            }
        }

        //
        // Pattern 7: pop-pop-ret sequence detection
        // Classic SEH exploitation pattern. pop = 58-5F (pop rax..rdi).
        // Look for 2+ consecutive pops followed by ret within window.
        //
        if (!(result & CsaAnomaly_ReturnGadget) && prevByte == CSA_RET_OPCODE) {
            ULONG popCount = 0;
            for (int k = CSA_ROP_GADGET_WINDOW - 2; k >= 0; k--) {
                UCHAR byte = codeBuffer[k];
                if (byte >= 0x58 && byte <= 0x5F) {
                    popCount++;
                } else {
                    break;
                }
            }
            if (popCount >= 2) {
                result |= CsaAnomaly_ReturnGadget;
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Access violation reading user memory — address may be unmapped.
        // Return what we have (likely nothing), don't flag as error.
        //
    }

    KeUnstackDetachProcess(&apcState);

    return result;
}


//=============================================================================
// Internal Functions — Suspicion Scoring
//=============================================================================

static
_Use_decl_annotations_
ULONG
CsapCalculateSuspicionScore(
    _In_ PCSA_CALLSTACK Callstack
    )
{
    ULONG score = 0;
    ULONG i;
    ULONG unbackedCount = 0;
    ULONG rwxCount = 0;

    if (Callstack == NULL || Callstack->FrameCount == 0) {
        return 0;
    }

    for (i = 0; i < Callstack->FrameCount; i++) {
        CSA_ANOMALY flags = Callstack->Frames[i].AnomalyFlags;

        if (flags & CsaAnomaly_UnbackedCode) unbackedCount++;
        if (flags & CsaAnomaly_RWXMemory)    rwxCount++;
    }

    //
    // Per-category scoring with individual caps to prevent any single
    // category from dominating the score.
    //

    // Unbacked code: base 250 + 50/frame, capped at 450
    if (Callstack->AggregatedAnomalies & CsaAnomaly_UnbackedCode) {
        ULONG cat = 250 + min(unbackedCount, 4) * 50;
        score += min(cat, 450);
    }

    // RWX memory: base 200 + 50/region, capped at 350
    if (Callstack->AggregatedAnomalies & CsaAnomaly_RWXMemory) {
        ULONG cat = 200 + min(rwxCount, 3) * 50;
        score += min(cat, 350);
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_StackPivot) {
        score += 400;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_MissingFrames) {
        score += 150;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_SpoofedFrames) {
        score += 300;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_UnknownModule) {
        score += 100;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_DirectSyscall) {
        score += 500;
    }

    if (Callstack->AggregatedAnomalies & CsaAnomaly_ReturnGadget) {
        score += 400;
    }

    //
    // Multi-anomaly bonus: 3+ distinct types indicate coordinated evasion
    //
    ULONG anomalyTypes = 0;
    CSA_ANOMALY temp = Callstack->AggregatedAnomalies;
    while (temp) {
        anomalyTypes += (temp & 1);
        temp >>= 1;
    }

    if (anomalyTypes >= 3) {
        score += 200;
    }

    return min(score, 1000);
}

