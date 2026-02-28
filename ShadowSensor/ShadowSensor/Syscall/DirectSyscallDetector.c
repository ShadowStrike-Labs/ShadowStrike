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
 * ShadowStrike NGAV - ENTERPRISE DIRECT SYSCALL DETECTION ENGINE
 * ============================================================================
 *
 * @file DirectSyscallDetector.c
 * @brief Enterprise-grade direct syscall abuse detection engine.
 *
 * Detection coverage:
 * - Direct syscall (mov eax, SSN; syscall)
 * - Indirect syscall (jmp to ntdll syscall stub)
 * - Heaven's Gate (WoW64 32->64 bit transition abuse)
 * - Hell's Gate (dynamic SSN resolution via PE parsing)
 * - Halo's Gate (neighbor syscall walking)
 * - Tartarus Gate (exception-based SSN resolution)
 * - SysWhispers v1/v2/v3 signatures
 * - Call stack integrity validation
 *
 * MITRE ATT&CK: T1106, T1055, T1620, T1562.001
 *
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "DirectSyscallDetector.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../../Shared/KernelProcessTypes.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define DSD_MAX_DETECTIONS                  4096
#define DSD_MAX_WHITELIST_PATTERNS          256
#define DSD_DETECTION_LOOKASIDE_DEPTH       128
#define DSD_MAX_STACK_DEPTH                 64
#define DSD_MIN_INSTRUCTION_BYTES           16
#define DSD_MAX_INSTRUCTION_BYTES           64

#define DSD_DETECTOR_MAGIC                  0x44534454  // 'DSDT'
#define DSD_DETECTION_MAGIC                 0x44534443  // 'DSDC'

#define DSD_WHITELIST_TAG                   'WLSD'
#define DSD_DETECTION_TAG                   'DESD'

#define DSD_HIGH_SUSPICION_THRESHOLD        75
#define DSD_MEDIUM_SUSPICION_THRESHOLD      50

#define DSD_MAX_MODULE_WALK_ITERATIONS      512
#define DSD_NTDLL_NAME                      L"ntdll.dll"
#define DSD_SHUTDOWN_TIMEOUT_MS             5000
#define DSD_RATE_LIMIT_WINDOW_100NS         10000000LL  // 1 second in 100ns units
#define DSD_MAX_MODULE_NAME_CHARS           260

// ============================================================================
// SYSCALL INSTRUCTION PATTERNS
// ============================================================================

#define DSD_SYSCALL_OPCODE_0                0x0F
#define DSD_SYSCALL_OPCODE_1                0x05

#define DSD_SYSENTER_OPCODE_0               0x0F
#define DSD_SYSENTER_OPCODE_1               0x34

#define DSD_INT2E_OPCODE_0                  0xCD
#define DSD_INT2E_OPCODE_1                  0x2E

#define DSD_MOV_EAX_IMM32                   0xB8

#define DSD_MOV_R10_RCX_0                   0x4C
#define DSD_MOV_R10_RCX_1                   0x8B
#define DSD_MOV_R10_RCX_2                   0xD1

#define DSD_JMP_REL32                       0xE9
#define DSD_JMP_RIP_DISP32_0                0xFF
#define DSD_JMP_RIP_DISP32_1                0x25
#define DSD_CALL_REL32                      0xE8
#define DSD_RET                             0xC3

#define DSD_HEAVENS_GATE_SEGMENT            0x33
#define DSD_FAR_JMP                         0xEA
#define DSD_RETF                            0xCB

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// The opaque DSD_DETECTOR defined in the header is actually this:
//
struct _DSD_DETECTOR {
    BOOLEAN Initialized;

    //
    // Detection record history (internal ring buffer)
    //
    LIST_ENTRY DetectionList;
    EX_PUSH_LOCK DetectionLock;
    volatile LONG DetectionCount;

    //
    // Whitelist — separate lock to avoid contention with detection list
    //
    LIST_ENTRY WhitelistPatterns;
    EX_PUSH_LOCK WhitelistLock;

    DSD_DETECTOR_STATS Stats;
};

typedef struct _DSD_DETECTOR_INTERNAL {
    //
    // Public base (must be first for safe cast)
    //
    DSD_DETECTOR Base;

    ULONG Magic;

    //
    // Lookaside list for detection allocations
    //
    NPAGED_LOOKASIDE_LIST DetectionLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Per-process NTDLL information is resolved on each call via
    // PEB/LDR walking with KeStackAttachProcess. No global cache
    // since ASLR randomizes per-process.
    //

    //
    // Reference counting for safe shutdown
    //
    volatile LONG ReferenceCount;
    volatile LONG ShuttingDown;
    KEVENT ShutdownEvent;

    //
    // Rate limiting
    //
    volatile LONG64 AnalysisCountInWindow;
    volatile LONG64 LastRateLimitReset;  // KeQueryPerformanceCounter ticks
    ULONG RateLimitPerSecond;

} DSD_DETECTOR_INTERNAL, *PDSD_DETECTOR_INTERNAL;

//
// Tracking whether a detection was allocated from the lookaside or pool.
//
typedef enum _DSD_ALLOC_SOURCE {
    DsdAllocSource_Lookaside = 1,
    DsdAllocSource_Pool      = 2
} DSD_ALLOC_SOURCE;

typedef struct _DSD_DETECTION_INTERNAL {
    //
    // Public snapshot (returned to caller as a detached copy)
    //
    DSD_DETECTION Base;

    //
    // Internal list linkage — NOT exposed to callers
    //
    LIST_ENTRY ListEntry;

    ULONG Magic;
    DSD_ALLOC_SOURCE AllocSource;

    UCHAR InstructionBytes[DSD_MAX_INSTRUCTION_BYTES];
    ULONG InstructionLength;

    BOOLEAN HasMovEax;
    BOOLEAN HasMovR10Rcx;
    BOOLEAN HasSyscallInstruction;
    BOOLEAN HasJmpToNtdll;
    BOOLEAN HasReturnToNtdll;

    BOOLEAN HasDynamicSsnResolution;
    BOOLEAN HasSegmentSwitch;
    UCHAR TargetSegment;

    ULONG SysWhispersVersion;
    BOOLEAN HasSysWhispersPattern;

} DSD_DETECTION_INTERNAL, *PDSD_DETECTION_INTERNAL;

typedef struct _DSD_WHITELIST_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING ModuleName;
    ULONG64 BaseAddress;
    SIZE_T Size;
    BOOLEAN MatchByName;
    BOOLEAN MatchByAddress;
} DSD_WHITELIST_ENTRY, *PDSD_WHITELIST_ENTRY;

//
// Resolved NTDLL info for a specific process — stack-allocated per call
//
typedef struct _DSD_NTDLL_INFO {
    ULONG_PTR Base;
    SIZE_T    Size;
    BOOLEAN   Valid;
} DSD_NTDLL_INFO, *PDSD_NTDLL_INFO;

//
// Resolved module info — stack-allocated per call
//
typedef struct _DSD_MODULE_INFO {
    ULONG_PTR Base;
    SIZE_T    Size;
    WCHAR     Name[DSD_MAX_MODULE_NAME_CHARS];
    BOOLEAN   Found;
} DSD_MODULE_INFO, *PDSD_MODULE_INFO;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static BOOLEAN
DsdpTryAcquireReference(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
);

static VOID
DsdpReleaseReference(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
);

static NTSTATUS
DsdpAllocateDetection(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _Out_ PDSD_DETECTION_INTERNAL* Detection
);

static VOID
DsdpFreeDetectionInternal(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PDSD_DETECTION_INTERNAL Detection
);

static BOOLEAN
DsdpIsDirectSyscallPattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG SyscallNumber
);

static BOOLEAN
DsdpIsIndirectSyscallPattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PVOID CallerRip,
    _In_ PDSD_NTDLL_INFO NtdllInfo
);

static BOOLEAN
DsdpIsHeavensGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length
);

static BOOLEAN
DsdpIsHellsGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _Inout_opt_ PDSD_DETECTION_INTERNAL Detection
);

static BOOLEAN
DsdpIsHalosGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length
);

static BOOLEAN
DsdpIsTartarusGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length
);

static BOOLEAN
DsdpIsSysWhispersPattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG Version
);

static NTSTATUS
DsdpCaptureUserCallStack(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_writes_(MaxFrames) PVOID* Frames,
    _In_ ULONG MaxFrames,
    _Out_ PULONG CapturedFrames
);

static NTSTATUS
DsdpResolveNtdllForProcess(
    _In_ HANDLE ProcessId,
    _Out_ PDSD_NTDLL_INFO NtdllInfo
);

static NTSTATUS
DsdpFindModuleForAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PDSD_MODULE_INFO ModuleInfo
);

static NTSTATUS
DsdpSafeReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
);

static ULONG
DsdpCalculateSuspicionScore(
    _In_ PDSD_DETECTION_INTERNAL Detection
);

static BOOLEAN
DsdpIsWhitelisted(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_opt_ PCWSTR ModuleName
);

static BOOLEAN
DsdpCheckRateLimit(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DsdInitialize)
#pragma alloc_text(PAGE, DsdShutdown)
#pragma alloc_text(PAGE, DsdAnalyzeSyscall)
#pragma alloc_text(PAGE, DsdDetectTechnique)
#pragma alloc_text(PAGE, DsdValidateCallstack)
#pragma alloc_text(PAGE, DsdFreeDetection)
#endif

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdInitialize(
    _Out_ PDSD_DETECTOR* Detector
)
{
    PDSD_DETECTOR_INTERNAL detector = NULL;
    LARGE_INTEGER now;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    detector = (PDSD_DETECTOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(DSD_DETECTOR_INTERNAL),
        DSD_POOL_TAG
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detector, sizeof(DSD_DETECTOR_INTERNAL));

    detector->Magic = DSD_DETECTOR_MAGIC;

    InitializeListHead(&detector->Base.DetectionList);
    ExInitializePushLock(&detector->Base.DetectionLock);

    InitializeListHead(&detector->Base.WhitelistPatterns);
    ExInitializePushLock(&detector->Base.WhitelistLock);

    ExInitializeNPagedLookasideList(
        &detector->DetectionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(DSD_DETECTION_INTERNAL),
        DSD_DETECTION_TAG,
        DSD_DETECTION_LOOKASIDE_DEPTH
    );
    detector->LookasideInitialized = TRUE;

    detector->ReferenceCount = 1;
    detector->ShuttingDown = FALSE;
    KeInitializeEvent(&detector->ShutdownEvent, NotificationEvent, FALSE);

    detector->RateLimitPerSecond = 10000;

    KeQuerySystemTime(&now);
    detector->Base.Stats.StartTime = now;
    InterlockedExchange64(&detector->LastRateLimitReset, now.QuadPart);

    detector->Base.Initialized = TRUE;

    *Detector = &detector->Base;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
DsdShutdown(
    _Inout_ PDSD_DETECTOR Detector
)
{
    PDSD_DETECTOR_INTERNAL detector;
    PLIST_ENTRY entry;
    PDSD_DETECTION_INTERNAL detection;
    PDSD_WHITELIST_ENTRY whitelist;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, DSD_DETECTOR_INTERNAL, Base);

    if (detector->Magic != DSD_DETECTOR_MAGIC) {
        return;
    }

    //
    // Signal shutdown — all new TryAcquireReference calls will fail
    //
    InterlockedExchange(&detector->ShuttingDown, 1);

    //
    // Release the initial reference (set in DsdInitialize)
    //
    DsdpReleaseReference(detector);

    //
    // Wait for all outstanding references to drain, with a bounded timeout.
    // Use KeClearEvent + atomic check to avoid TOCTOU race.
    //
    KeClearEvent(&detector->ShutdownEvent);
    if (InterlockedCompareExchange(&detector->ReferenceCount, 0, 0) > 0) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)DSD_SHUTDOWN_TIMEOUT_MS * 10000LL;  // relative, ms -> 100ns
        KeWaitForSingleObject(
            &detector->ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Free all detection records under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->DetectionLock);

    while (!IsListEmpty(&Detector->DetectionList)) {
        entry = RemoveHeadList(&Detector->DetectionList);
        detection = CONTAINING_RECORD(entry, DSD_DETECTION_INTERNAL, ListEntry);
        DsdpFreeDetectionInternal(detector, detection);
    }

    ExReleasePushLockExclusive(&Detector->DetectionLock);
    KeLeaveCriticalRegion();

    //
    // Free whitelist entries under whitelist lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->WhitelistLock);

    while (!IsListEmpty(&Detector->WhitelistPatterns)) {
        entry = RemoveHeadList(&Detector->WhitelistPatterns);
        whitelist = CONTAINING_RECORD(entry, DSD_WHITELIST_ENTRY, ListEntry);

        if (whitelist->ModuleName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(whitelist->ModuleName.Buffer, DSD_WHITELIST_TAG);
        }

        ShadowStrikeFreePoolWithTag(whitelist, DSD_WHITELIST_TAG);
    }

    ExReleasePushLockExclusive(&Detector->WhitelistLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside
    //
    if (detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&detector->DetectionLookaside);
        detector->LookasideInitialized = FALSE;
    }

    detector->Magic = 0;
    Detector->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(detector, DSD_POOL_TAG);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdAnalyzeSyscall(
    _In_ PDSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID CallerAddress,
    _In_ ULONG SyscallNumber,
    _Out_ PDSD_DETECTION* Detection
)
{
    NTSTATUS status;
    PDSD_DETECTOR_INTERNAL detector;
    PDSD_DETECTION_INTERNAL detection = NULL;
    UCHAR instructionBuffer[DSD_MAX_INSTRUCTION_BYTES];
    ULONG capturedLength = 0;
    DSD_TECHNIQUE technique = DsdTechnique_None;
    ULONG sysWhispersVersion = 0;
    DSD_NTDLL_INFO ntdllInfo = { 0 };
    DSD_MODULE_INFO moduleInfo = { 0 };

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    detector = CONTAINING_RECORD(Detector, DSD_DETECTOR_INTERNAL, Base);

    if (detector->Magic != DSD_DETECTOR_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallerAddress == NULL || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Detection == NULL) {
        return STATUS_INVALID_PARAMETER_6;
    }

    *Detection = NULL;

    //
    // Validate caller address is in user space using the framework utility
    //
    if (!ShadowStrikeIsValidUserAddressRange(CallerAddress, DSD_MIN_INSTRUCTION_BYTES)) {
        return STATUS_INVALID_ADDRESS;
    }

    //
    // Try-acquire reference — fails atomically if shutting down
    //
    if (!DsdpTryAcquireReference(detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Rate limit enforcement
    //
    if (!DsdpCheckRateLimit(detector)) {
        InterlockedIncrement64(&detector->Base.Stats.RateLimitDrops);
        DsdpReleaseReference(detector);
        return STATUS_QUOTA_EXCEEDED;
    }

    InterlockedIncrement64(&detector->Base.Stats.SyscallsAnalyzed);

    //
    // Check whitelist first (no heavy work needed if whitelisted)
    //
    if (DsdpIsWhitelisted(detector, CallerAddress, NULL)) {
        DsdpReleaseReference(detector);
        return STATUS_NO_MORE_ENTRIES;
    }

    //
    // Read instruction bytes from the target process's address space.
    // This attaches to the process context internally.
    //
    RtlZeroMemory(instructionBuffer, sizeof(instructionBuffer));

    status = DsdpSafeReadProcessMemory(
        ProcessId,
        CallerAddress,
        instructionBuffer,
        DSD_MAX_INSTRUCTION_BYTES
    );

    if (!NT_SUCCESS(status)) {
        status = DsdpSafeReadProcessMemory(
            ProcessId,
            CallerAddress,
            instructionBuffer,
            DSD_MIN_INSTRUCTION_BYTES
        );

        if (!NT_SUCCESS(status)) {
            DsdpReleaseReference(detector);
            return status;
        }
        capturedLength = DSD_MIN_INSTRUCTION_BYTES;
    } else {
        capturedLength = DSD_MAX_INSTRUCTION_BYTES;
    }

    //
    // Resolve NTDLL base for this specific process (ASLR-aware)
    //
    DsdpResolveNtdllForProcess(ProcessId, &ntdllInfo);

    //
    // Allocate detection record
    //
    status = DsdpAllocateDetection(detector, &detection);
    if (!NT_SUCCESS(status)) {
        DsdpReleaseReference(detector);
        return status;
    }

    detection->Base.ProcessId = ProcessId;
    detection->Base.ThreadId = ThreadId;
    detection->Base.CallerAddress = CallerAddress;
    detection->Base.SyscallNumber = SyscallNumber;
    KeQuerySystemTime(&detection->Base.Timestamp);

    RtlCopyMemory(detection->InstructionBytes, instructionBuffer, capturedLength);
    detection->InstructionLength = capturedLength;

    //
    // Pattern analysis — ordered by specificity (most specific first)
    //

    ULONG detectedSsn = 0;

    // 1. SysWhispers (very specific byte sequences)
    if (DsdpIsSysWhispersPattern(instructionBuffer, capturedLength, &sysWhispersVersion)) {
        technique = DsdTechnique_SysWhispers;
        detection->HasSysWhispersPattern = TRUE;
        detection->SysWhispersVersion = sysWhispersVersion;
        InterlockedIncrement64(&detector->Base.Stats.SysWhispersCalls);
    }

    // 2. Direct syscall
    if (technique == DsdTechnique_None &&
        DsdpIsDirectSyscallPattern(instructionBuffer, capturedLength, &detectedSsn)) {
        technique = DsdTechnique_DirectSyscall;
        detection->HasMovEax = TRUE;
        detection->HasSyscallInstruction = TRUE;
        InterlockedIncrement64(&detector->Base.Stats.DirectCalls);
    }

    // 3. Heaven's Gate
    if (technique == DsdTechnique_None &&
        DsdpIsHeavensGatePattern(instructionBuffer, capturedLength)) {
        technique = DsdTechnique_HeavensGate;
        detection->HasSegmentSwitch = TRUE;
        detection->TargetSegment = DSD_HEAVENS_GATE_SEGMENT;
        InterlockedIncrement64(&detector->Base.Stats.HeavensGateCalls);
    }

    // 4. Hell's Gate
    if (technique == DsdTechnique_None &&
        DsdpIsHellsGatePattern(instructionBuffer, capturedLength, detection)) {
        technique = DsdTechnique_HellsGate;
        detection->HasDynamicSsnResolution = TRUE;
        InterlockedIncrement64(&detector->Base.Stats.HellsGateCalls);
    }

    // 5. Halo's Gate
    if (technique == DsdTechnique_None &&
        DsdpIsHalosGatePattern(instructionBuffer, capturedLength)) {
        technique = DsdTechnique_HalosGate;
        InterlockedIncrement64(&detector->Base.Stats.HalosGateCalls);
    }

    // 6. Tartarus Gate
    if (technique == DsdTechnique_None &&
        DsdpIsTartarusGatePattern(instructionBuffer, capturedLength)) {
        technique = DsdTechnique_TartarusGate;
        InterlockedIncrement64(&detector->Base.Stats.TartarusGateCalls);
    }

    // 7. Indirect syscall (requires real RIP for displacement calc)
    if (technique == DsdTechnique_None && ntdllInfo.Valid) {
        if (DsdpIsIndirectSyscallPattern(instructionBuffer, capturedLength,
                                          CallerAddress, &ntdllInfo)) {
            technique = DsdTechnique_IndirectSyscall;
            detection->HasJmpToNtdll = TRUE;
            InterlockedIncrement64(&detector->Base.Stats.IndirectCalls);
        }
    }

    detection->Base.Technique = technique;

    //
    // Resolve caller module via PEB/LDR walking
    //
    status = DsdpFindModuleForAddress(ProcessId, CallerAddress, &moduleInfo);
    if (NT_SUCCESS(status) && moduleInfo.Found) {
        detection->Base.CallFromKnownModule = TRUE;
        detection->Base.CallerModuleBase = moduleInfo.Base;
        detection->Base.CallerModuleSize = moduleInfo.Size;
        detection->Base.CallerOffset = (ULONG64)CallerAddress - moduleInfo.Base;

        RtlStringCchCopyW(
            detection->Base.CallerModuleName,
            DSD_MAX_MODULE_NAME_CHARS,
            moduleInfo.Name
        );

        //
        // Check if the module is ntdll.dll
        //
        if (_wcsicmp(moduleInfo.Name, DSD_NTDLL_NAME) == 0) {
            detection->Base.CallFromNtdll = TRUE;
        }
    } else {
        detection->Base.CallFromKnownModule = FALSE;
        detection->Base.CallFromNtdll = FALSE;
    }

    //
    // Capture user-mode call stack (properly attached to target process)
    //
    status = DsdpCaptureUserCallStack(
        ProcessId,
        ThreadId,
        detection->Base.ReturnAddresses,
        ARRAYSIZE(detection->Base.ReturnAddresses),
        &detection->Base.ReturnAddressCount
    );

    if (NT_SUCCESS(status) && detection->Base.ReturnAddressCount > 0 && ntdllInfo.Valid) {
        for (ULONG i = 0; i < detection->Base.ReturnAddressCount; i++) {
            ULONG_PTR retAddr = (ULONG_PTR)detection->Base.ReturnAddresses[i];
            if (retAddr >= ntdllInfo.Base &&
                (retAddr - ntdllInfo.Base) < ntdllInfo.Size) {
                detection->HasReturnToNtdll = TRUE;
                break;
            }
        }
    }

    detection->Base.SuspicionScore = DsdpCalculateSuspicionScore(detection);

    //
    // Produce result: return a detached copy to the caller, or discard.
    // The caller owns the pointer and must free it with DsdFreeDetection.
    //
    if (technique != DsdTechnique_None ||
        detection->Base.SuspicionScore >= DSD_MEDIUM_SUSPICION_THRESHOLD) {

        *Detection = &detection->Base;

    } else {
        DsdpFreeDetectionInternal(detector, detection);
        DsdpReleaseReference(detector);
        return STATUS_NOT_FOUND;
    }

    DsdpReleaseReference(detector);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdDetectTechnique(
    _In_ PDSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID CallerRip,
    _In_ PVOID Address,
    _In_ ULONG Length,
    _Out_ PDSD_TECHNIQUE Technique
)
{
    NTSTATUS status;
    PDSD_DETECTOR_INTERNAL detector;
    PUCHAR buffer = NULL;
    ULONG sysWhispersVersion = 0;
    ULONG detectedSsn = 0;
    DSD_NTDLL_INFO ntdllInfo = { 0 };

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    detector = CONTAINING_RECORD(Detector, DSD_DETECTOR_INTERNAL, Base);

    if (detector->Magic != DSD_DETECTOR_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL || Address == NULL || CallerRip == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Length == 0 || Length > DSD_MAX_INSTRUCTION_BYTES) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Technique == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Technique = DsdTechnique_None;

    //
    // Validate address is user-mode
    //
    if (!ShadowStrikeIsValidUserAddressRange(Address, Length)) {
        return STATUS_INVALID_ADDRESS;
    }

    if (!DsdpTryAcquireReference(detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    buffer = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Length,
        DSD_POOL_TAG
    );

    if (buffer == NULL) {
        DsdpReleaseReference(detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read from target process with proper process attachment
    //
    status = DsdpSafeReadProcessMemory(ProcessId, Address, buffer, Length);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(buffer, DSD_POOL_TAG);
        DsdpReleaseReference(detector);
        return status;
    }

    //
    // Resolve NTDLL for indirect syscall analysis
    //
    DsdpResolveNtdllForProcess(ProcessId, &ntdllInfo);

    //
    // Check patterns in order of specificity
    //
    if (DsdpIsSysWhispersPattern(buffer, Length, &sysWhispersVersion)) {
        *Technique = DsdTechnique_SysWhispers;
        goto Cleanup;
    }

    if (DsdpIsDirectSyscallPattern(buffer, Length, &detectedSsn)) {
        *Technique = DsdTechnique_DirectSyscall;
        goto Cleanup;
    }

    if (DsdpIsHeavensGatePattern(buffer, Length)) {
        *Technique = DsdTechnique_HeavensGate;
        goto Cleanup;
    }

    if (DsdpIsHellsGatePattern(buffer, Length, NULL)) {
        *Technique = DsdTechnique_HellsGate;
        goto Cleanup;
    }

    if (DsdpIsHalosGatePattern(buffer, Length)) {
        *Technique = DsdTechnique_HalosGate;
        goto Cleanup;
    }

    if (DsdpIsTartarusGatePattern(buffer, Length)) {
        *Technique = DsdTechnique_TartarusGate;
        goto Cleanup;
    }

    if (ntdllInfo.Valid &&
        DsdpIsIndirectSyscallPattern(buffer, Length, CallerRip, &ntdllInfo)) {
        *Technique = DsdTechnique_IndirectSyscall;
        goto Cleanup;
    }

Cleanup:
    ShadowStrikeFreePoolWithTag(buffer, DSD_POOL_TAG);
    DsdpReleaseReference(detector);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdValidateCallstack(
    _In_ PDSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsValid,
    _Out_opt_ PDSD_TECHNIQUE Technique
)
{
    NTSTATUS status;
    PDSD_DETECTOR_INTERNAL detector;
    PVOID frames[DSD_MAX_STACK_DEPTH];
    ULONG frameCount = 0;
    BOOLEAN hasNtdllFrame = FALSE;
    ULONG unknownFrameCount = 0;
    DSD_TECHNIQUE detectedTechnique = DsdTechnique_None;
    DSD_NTDLL_INFO ntdllInfo = { 0 };

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    detector = CONTAINING_RECORD(Detector, DSD_DETECTOR_INTERNAL, Base);

    if (detector->Magic != DSD_DETECTOR_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL || ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (IsValid == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *IsValid = TRUE;
    if (Technique != NULL) {
        *Technique = DsdTechnique_None;
    }

    if (!DsdpTryAcquireReference(detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Capture user-mode call stack (with process attachment)
    //
    status = DsdpCaptureUserCallStack(
        ProcessId,
        ThreadId,
        frames,
        DSD_MAX_STACK_DEPTH,
        &frameCount
    );

    if (!NT_SUCCESS(status)) {
        DsdpReleaseReference(detector);
        return status;
    }

    if (frameCount == 0) {
        *IsValid = FALSE;
        DsdpReleaseReference(detector);
        return STATUS_SUCCESS;
    }

    //
    // Resolve NTDLL for this process
    //
    DsdpResolveNtdllForProcess(ProcessId, &ntdllInfo);

    for (ULONG i = 0; i < frameCount; i++) {
        PVOID frame = frames[i];
        if (frame == NULL) {
            continue;
        }

        if (ntdllInfo.Valid) {
            ULONG_PTR addr = (ULONG_PTR)frame;
            if (addr >= ntdllInfo.Base && addr < ntdllInfo.Base + ntdllInfo.Size) {
                hasNtdllFrame = TRUE;
                continue;
            }
        }

        //
        // Check if frame is in any known module via PEB walk
        //
        DSD_MODULE_INFO modInfo = { 0 };
        status = DsdpFindModuleForAddress(ProcessId, frame, &modInfo);
        if (!NT_SUCCESS(status) || !modInfo.Found) {
            unknownFrameCount++;
        }
    }

    if (!hasNtdllFrame && ntdllInfo.Valid) {
        *IsValid = FALSE;
        detectedTechnique = DsdTechnique_DirectSyscall;
    }

    if (unknownFrameCount > 0) {
        *IsValid = FALSE;
        if (unknownFrameCount >= 3) {
            detectedTechnique = DsdTechnique_Manual;
        }
    }

    //
    // Check first frame for Heaven's Gate
    //
    if (frameCount > 0 && frames[0] != NULL &&
        ShadowStrikeIsUserAddress(frames[0])) {

        UCHAR instructionBuffer[16];
        status = DsdpSafeReadProcessMemory(
            ProcessId, frames[0], instructionBuffer, sizeof(instructionBuffer)
        );
        if (NT_SUCCESS(status)) {
            if (DsdpIsHeavensGatePattern(instructionBuffer, sizeof(instructionBuffer))) {
                *IsValid = FALSE;
                detectedTechnique = DsdTechnique_HeavensGate;
            }
        }
    }

    if (Technique != NULL) {
        *Technique = detectedTechnique;
    }

    DsdpReleaseReference(detector);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
DsdFreeDetection(
    _In_ _Post_ptr_invalid_ PDSD_DETECTION Detection
)
{
    PDSD_DETECTION_INTERNAL detection;

    PAGED_CODE();

    if (Detection == NULL) {
        return;
    }

    detection = CONTAINING_RECORD(Detection, DSD_DETECTION_INTERNAL, Base);

    if (detection->Magic != DSD_DETECTION_MAGIC) {
        return;
    }

    //
    // Detections returned to callers are NOT on any list. Just free.
    //
    detection->Magic = 0;

    if (detection->AllocSource == DsdAllocSource_Pool) {
        ShadowStrikeFreePoolWithTag(detection, DSD_DETECTION_TAG);
    } else {
        //
        // Cannot safely return to lookaside without the detector pointer.
        // The detection was detached — use pool free with the detection tag.
        // This is safe: ExFreePoolWithTag works regardless of original allocator.
        //
        ShadowStrikeFreePoolWithTag(detection, DSD_DETECTION_TAG);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

/**
 * @brief Atomically increments reference count if not shutting down.
 * @return TRUE if reference was acquired, FALSE if shutting down.
 */
static BOOLEAN
DsdpTryAcquireReference(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
)
{
    //
    // InterlockedIncrement then check ShuttingDown. If shutting down,
    // undo the increment. This prevents the shutdown race:
    // - Caller sees ShuttingDown == FALSE
    // - Shutdown starts between check and increment
    // - Caller bumps refcount after shutdown started draining
    //
    InterlockedIncrement(&Detector->ReferenceCount);

    if (Detector->ShuttingDown) {
        DsdpReleaseReference(Detector);
        return FALSE;
    }

    return TRUE;
}

static VOID
DsdpReleaseReference(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
)
{
    LONG newCount = InterlockedDecrement(&Detector->ReferenceCount);

    if (newCount == 0 && Detector->ShuttingDown) {
        KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ALLOCATION
// ============================================================================

static NTSTATUS
DsdpAllocateDetection(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _Out_ PDSD_DETECTION_INTERNAL* Detection
)
{
    PDSD_DETECTION_INTERNAL detection = NULL;
    DSD_ALLOC_SOURCE source = DsdAllocSource_Pool;

    *Detection = NULL;

    if (Detector->LookasideInitialized) {
        detection = (PDSD_DETECTION_INTERNAL)ExAllocateFromNPagedLookasideList(
            &Detector->DetectionLookaside
        );
        if (detection != NULL) {
            source = DsdAllocSource_Lookaside;
        }
    }

    if (detection == NULL) {
        detection = (PDSD_DETECTION_INTERNAL)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(DSD_DETECTION_INTERNAL),
            DSD_DETECTION_TAG
        );
        source = DsdAllocSource_Pool;
    }

    if (detection == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detection, sizeof(DSD_DETECTION_INTERNAL));

    detection->Magic = DSD_DETECTION_MAGIC;
    detection->AllocSource = source;
    InitializeListHead(&detection->ListEntry);

    *Detection = detection;

    return STATUS_SUCCESS;
}

static VOID
DsdpFreeDetectionInternal(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PDSD_DETECTION_INTERNAL Detection
)
{
    if (Detection == NULL) {
        return;
    }

    Detection->Magic = 0;

    //
    // Free based on actual allocation source — no cross-free between
    // lookaside and pool.
    //
    if (Detection->AllocSource == DsdAllocSource_Lookaside &&
        Detector->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Detector->DetectionLookaside, Detection);
    } else {
        ShadowStrikeFreePoolWithTag(Detection, DSD_DETECTION_TAG);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROCESS-AWARE MEMORY ACCESS
// ============================================================================

/**
 * @brief Reads memory from a target process with proper process attachment.
 *
 * Attaches to the target process address space, probes the user address,
 * and copies data to a kernel buffer. Safe against process exit races.
 */
static NTSTATUS
DsdpSafeReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    if (!ShadowStrikeIsValidUserAddressRange(SourceAddress, Length)) {
        return STATUS_INVALID_ADDRESS;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(SourceAddress, Length, 1);
        RtlCopyMemory(Destination, SourceAddress, Length);
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

/**
 * @brief Resolves ntdll.dll base and size for a specific process.
 *
 * Walks the PEB InMemoryOrderModuleList to find ntdll.dll. This handles
 * ASLR correctly since each process has its own ntdll mapping.
 */
static NTSTATUS
DsdpResolveNtdllForProcess(
    _In_ HANDLE ProcessId,
    _Out_ PDSD_NTDLL_INFO NtdllInfo
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPEB peb = NULL;
    KAPC_STATE apcState;
    ULONG iterationCount = 0;

    NtdllInfo->Base = 0;
    NtdllInfo->Size = 0;
    NtdllInfo->Valid = FALSE;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    peb = PsGetProcessPeb(process);
    if (peb == NULL) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        PKM_PEB_LDR_DATA ldrData;

        ProbeForRead(peb, KM_PEB_PROBE_SIZE, sizeof(PVOID));
        ldrData = (PKM_PEB_LDR_DATA)((PKM_PEB)peb)->Ldr;

        if (ldrData == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(ldrData, KM_PEB_LDR_PROBE_SIZE, sizeof(PVOID));

        PLIST_ENTRY listHead = &ldrData->InMemoryOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;

        while (listEntry != listHead &&
               iterationCount < DSD_MAX_MODULE_WALK_ITERATIONS) {

            PKM_LDR_DATA_TABLE_ENTRY ldrEntry;

            iterationCount++;

            ldrEntry = CONTAINING_RECORD(
                listEntry,
                KM_LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
            );

            ProbeForRead(ldrEntry, KM_LDR_ENTRY_PROBE_SIZE, sizeof(PVOID));

            if (ldrEntry->BaseDllName.Buffer != NULL &&
                ldrEntry->BaseDllName.Length > 0 &&
                ldrEntry->BaseDllName.Length < 520) {

                ProbeForRead(
                    ldrEntry->BaseDllName.Buffer,
                    ldrEntry->BaseDllName.Length,
                    sizeof(WCHAR)
                );

                //
                // Case-insensitive comparison against "ntdll.dll"
                //
                UNICODE_STRING ntdllName;
                RtlInitUnicodeString(&ntdllName, DSD_NTDLL_NAME);

                if (RtlEqualUnicodeString(&ldrEntry->BaseDllName, &ntdllName, TRUE)) {
                    NtdllInfo->Base = (ULONG_PTR)ldrEntry->DllBase;
                    NtdllInfo->Size = ldrEntry->SizeOfImage;
                    NtdllInfo->Valid = TRUE;
                    status = STATUS_SUCCESS;
                    __leave;
                }
            }

            listEntry = listEntry->Flink;
        }

        if (iterationCount >= DSD_MAX_MODULE_WALK_ITERATIONS) {
            status = STATUS_DATA_ERROR;
        } else {
            status = STATUS_NOT_FOUND;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

/**
 * @brief Finds the module containing a given address by walking PEB/LDR.
 */
static NTSTATUS
DsdpFindModuleForAddress(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PDSD_MODULE_INFO ModuleInfo
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPEB peb = NULL;
    KAPC_STATE apcState;
    ULONG iterationCount = 0;

    ModuleInfo->Base = 0;
    ModuleInfo->Size = 0;
    ModuleInfo->Name[0] = L'\0';
    ModuleInfo->Found = FALSE;

    if (!ShadowStrikeIsUserAddress(Address)) {
        return STATUS_INVALID_ADDRESS;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    peb = PsGetProcessPeb(process);
    if (peb == NULL) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        PKM_PEB_LDR_DATA ldrData;

        ProbeForRead(peb, KM_PEB_PROBE_SIZE, sizeof(PVOID));
        ldrData = (PKM_PEB_LDR_DATA)((PKM_PEB)peb)->Ldr;

        if (ldrData == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        ProbeForRead(ldrData, KM_PEB_LDR_PROBE_SIZE, sizeof(PVOID));

        PLIST_ENTRY listHead = &ldrData->InMemoryOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;

        while (listEntry != listHead &&
               iterationCount < DSD_MAX_MODULE_WALK_ITERATIONS) {

            PKM_LDR_DATA_TABLE_ENTRY ldrEntry;
            ULONG_PTR moduleStart;

            iterationCount++;

            ldrEntry = CONTAINING_RECORD(
                listEntry,
                KM_LDR_DATA_TABLE_ENTRY,
                InMemoryOrderLinks
            );

            ProbeForRead(ldrEntry, KM_LDR_ENTRY_PROBE_SIZE, sizeof(PVOID));

            moduleStart = (ULONG_PTR)ldrEntry->DllBase;

            //
            // Overflow-safe range check: (Address - moduleStart) < Size
            //
            if (ldrEntry->SizeOfImage != 0 &&
                (ULONG_PTR)Address >= moduleStart &&
                ((ULONG_PTR)Address - moduleStart) < ldrEntry->SizeOfImage) {

                ModuleInfo->Base = moduleStart;
                ModuleInfo->Size = ldrEntry->SizeOfImage;
                ModuleInfo->Found = TRUE;

                if (ldrEntry->BaseDllName.Buffer != NULL &&
                    ldrEntry->BaseDllName.Length > 0 &&
                    ldrEntry->BaseDllName.Length < 520) {

                    ProbeForRead(
                        ldrEntry->BaseDllName.Buffer,
                        ldrEntry->BaseDllName.Length,
                        sizeof(WCHAR)
                    );

                    USHORT copyLen = min(
                        ldrEntry->BaseDllName.Length,
                        (USHORT)((DSD_MAX_MODULE_NAME_CHARS - 1) * sizeof(WCHAR))
                    );

                    RtlCopyMemory(ModuleInfo->Name, ldrEntry->BaseDllName.Buffer, copyLen);
                    ModuleInfo->Name[copyLen / sizeof(WCHAR)] = L'\0';
                }

                status = STATUS_SUCCESS;
                __leave;
            }

            listEntry = listEntry->Flink;
        }

        status = (iterationCount >= DSD_MAX_MODULE_WALK_ITERATIONS)
            ? STATUS_DATA_ERROR
            : STATUS_NOT_FOUND;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - USER-MODE CALL STACK CAPTURE
// ============================================================================

/**
 * @brief Captures user-mode call stack for a thread in a target process.
 *
 * Attaches to the target process and uses RtlWalkFrameChain with
 * flag 1 (user-mode frames). Only callable at PASSIVE_LEVEL.
 */
static NTSTATUS
DsdpCaptureUserCallStack(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_writes_(MaxFrames) PVOID* Frames,
    _In_ ULONG MaxFrames,
    _Out_ PULONG CapturedFrames
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    ULONG capturedCount = 0;

    UNREFERENCED_PARAMETER(ThreadId);

    *CapturedFrames = 0;
    RtlZeroMemory(Frames, MaxFrames * sizeof(PVOID));

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        //
        // RtlWalkFrameChain with flag 1 captures user-mode frames.
        // This requires running in the target process's address space.
        //
        capturedCount = RtlWalkFrameChain(Frames, MaxFrames, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    *CapturedFrames = capturedCount;

    return status;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - RATE LIMITING
// ============================================================================

static BOOLEAN
DsdpCheckRateLimit(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
)
{
    LARGE_INTEGER now;
    LONG64 lastReset;
    LONG64 count;

    KeQuerySystemTime(&now);
    lastReset = InterlockedCompareExchange64(&Detector->LastRateLimitReset, 0, 0);

    //
    // If more than 1 second since last reset, reset the window
    //
    if ((now.QuadPart - lastReset) >= DSD_RATE_LIMIT_WINDOW_100NS) {
        InterlockedExchange64(&Detector->LastRateLimitReset, now.QuadPart);
        InterlockedExchange64(&Detector->AnalysisCountInWindow, 0);
    }

    count = InterlockedIncrement64(&Detector->AnalysisCountInWindow);
    return (count <= (LONG64)Detector->RateLimitPerSecond);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PATTERN DETECTION
// ============================================================================

/**
 * @brief Detect direct syscall: mov eax, SSN; [mov r10, rcx;] syscall/sysenter/int 2e
 *
 * Requires BOTH mov eax (SSN load) AND a syscall instruction within
 * DSD_MAX_INSTRUCTION_BYTES of each other, in the correct order.
 */
static BOOLEAN
DsdpIsDirectSyscallPattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG SyscallNumber
)
{
    BOOLEAN foundMovEax = FALSE;
    BOOLEAN foundSyscall = FALSE;
    ULONG ssn = 0;

    *SyscallNumber = 0;

    if (Length < 7) {
        return FALSE;
    }

    for (ULONG i = 0; i < Length - 1; i++) {

        // mov eax, imm32 (B8 XX XX XX XX) — must precede syscall
        if (!foundSyscall && Instructions[i] == DSD_MOV_EAX_IMM32 && i + 4 < Length) {
            ssn = *(PULONG)(&Instructions[i + 1]);
            //
            // Sanity: SSN should be a reasonable value (< 0x2000 on modern Windows)
            //
            if (ssn < 0x2000) {
                foundMovEax = TRUE;
            }
            i += 4;
            continue;
        }

        // mov r10, rcx (4C 8B D1) — optional, skip
        if (i + 2 < Length &&
            Instructions[i] == DSD_MOV_R10_RCX_0 &&
            Instructions[i + 1] == DSD_MOV_R10_RCX_1 &&
            Instructions[i + 2] == DSD_MOV_R10_RCX_2) {
            i += 2;
            continue;
        }

        // syscall (0F 05)
        if (Instructions[i] == DSD_SYSCALL_OPCODE_0 &&
            Instructions[i + 1] == DSD_SYSCALL_OPCODE_1) {
            foundSyscall = TRUE;
            break;
        }

        // sysenter (0F 34)
        if (Instructions[i] == DSD_SYSENTER_OPCODE_0 &&
            Instructions[i + 1] == DSD_SYSENTER_OPCODE_1) {
            foundSyscall = TRUE;
            break;
        }

        // int 2e (CD 2E)
        if (Instructions[i] == DSD_INT2E_OPCODE_0 &&
            Instructions[i + 1] == DSD_INT2E_OPCODE_1) {
            foundSyscall = TRUE;
            break;
        }
    }

    if (foundMovEax && foundSyscall) {
        *SyscallNumber = ssn;
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Detect indirect syscall: jmp to NTDLL syscall stub.
 *
 * Uses the actual CallerRip to compute real jmp targets for rel32
 * displacements, then checks if the target falls within NTDLL.
 * Also checks for mov eax,SSN preceding the jmp as additional context.
 */
static BOOLEAN
DsdpIsIndirectSyscallPattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PVOID CallerRip,
    _In_ PDSD_NTDLL_INFO NtdllInfo
)
{
    ULONG_PTR callerBase = (ULONG_PTR)CallerRip;
    BOOLEAN hasMovEax = FALSE;

    if (!NtdllInfo->Valid || NtdllInfo->Base == 0 || NtdllInfo->Size == 0) {
        return FALSE;
    }

    if (Length < 5) {
        return FALSE;
    }

    for (ULONG i = 0; i < Length; i++) {

        // Track if we've seen a mov eax, SSN
        if (Instructions[i] == DSD_MOV_EAX_IMM32 && i + 4 < Length) {
            ULONG ssn = *(PULONG)(&Instructions[i + 1]);
            if (ssn < 0x2000) {
                hasMovEax = TRUE;
            }
            i += 4;
            continue;
        }

        // jmp rel32 (E9 XX XX XX XX) — compute real target
        if (Instructions[i] == DSD_JMP_REL32 && i + 4 < Length) {
            LONG32 displacement = *(PLONG32)(&Instructions[i + 1]);
            ULONG_PTR instrAddr = callerBase + i;
            ULONG_PTR targetAddr = instrAddr + 5 + (LONG_PTR)displacement;

            if (targetAddr >= NtdllInfo->Base &&
                (targetAddr - NtdllInfo->Base) < NtdllInfo->Size) {
                //
                // A jmp into NTDLL preceded by mov eax,SSN is a strong
                // indicator of an indirect syscall stub.
                //
                if (hasMovEax) {
                    return TRUE;
                }
            }
            i += 4;
            continue;
        }
    }

    return FALSE;
}

/**
 * @brief Detect Heaven's Gate: segment switch from 32-bit to 64-bit mode.
 *
 * Looks for specific multi-byte patterns involving CS=0x33 transitions.
 */
static BOOLEAN
DsdpIsHeavensGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length
)
{
    if (Length < 7) {
        return FALSE;
    }

    for (ULONG i = 0; i < Length - 6; i++) {

        // far jmp with segment selector 0x33 (EA XX XX XX XX 33 00)
        if (Instructions[i] == DSD_FAR_JMP &&
            i + 6 < Length &&
            Instructions[i + 5] == DSD_HEAVENS_GATE_SEGMENT &&
            Instructions[i + 6] == 0x00) {
            return TRUE;
        }

        // push 0x33; ... retf  (within 8 bytes)
        if (Instructions[i] == 0x6A &&
            Instructions[i + 1] == DSD_HEAVENS_GATE_SEGMENT) {
            for (ULONG j = i + 2; j < Length && j < i + 10; j++) {
                if (Instructions[j] == DSD_RETF) {
                    return TRUE;
                }
            }
        }

        // push imm32; push 0x33; ... retf
        if (Instructions[i] == 0x68 && i + 9 < Length) {
            if (Instructions[i + 5] == 0x6A &&
                Instructions[i + 6] == DSD_HEAVENS_GATE_SEGMENT) {
                for (ULONG j = i + 7; j < Length && j < i + 15; j++) {
                    if (Instructions[j] == DSD_RETF) {
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

/**
 * @brief Detect Hell's Gate: dynamic SSN resolution via PE header parsing.
 *
 * Requires BOTH a PE header signature check (MZ/PE) AND an export table
 * access (offset 0x88) in the same instruction window. Single indicators
 * alone are not sufficient to avoid false positives.
 */
static BOOLEAN
DsdpIsHellsGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _Inout_opt_ PDSD_DETECTION_INTERNAL Detection
)
{
    BOOLEAN hasPeHeaderCheck = FALSE;
    BOOLEAN hasExportDirAccess = FALSE;
    BOOLEAN hasSyscallStubRead = FALSE;

    if (Length < 20) {
        return FALSE;
    }

    for (ULONG i = 0; i < Length - 6; i++) {

        //
        // Check for comparison with 'MZ' (0x5A4D)
        // Pattern: 66 81 ModRM XX 4D 5A  or  66 3D 4D 5A
        //
        if (i + 5 < Length && Instructions[i] == 0x66) {
            if (Instructions[i + 1] == 0x81 || Instructions[i + 1] == 0x3D) {
                //
                // Verify it's actually comparing against MZ
                //
                for (ULONG k = i + 2; k < i + 6 && k + 1 < Length; k++) {
                    USHORT val = *(PUSHORT)(&Instructions[k]);
                    if (val == 0x5A4D) {
                        hasPeHeaderCheck = TRUE;
                        break;
                    }
                }
            }
        }

        // Check for 'PE\0\0' comparison (0x00004550)
        if (i + 5 < Length && Instructions[i] == 0x81) {
            for (ULONG k = i + 2; k + 3 < Length && k < i + 4; k++) {
                if (*(PULONG)(&Instructions[k]) == 0x00004550) {
                    hasPeHeaderCheck = TRUE;
                    break;
                }
            }
        }

        //
        // Check for export directory offset (0x88) access in a MOV
        // This is the RVA of the export directory in the optional header.
        //
        if (i + 6 < Length && (Instructions[i] == 0x8B || Instructions[i] == 0x8D)) {
            // Look for displacement 0x88 in modrm/sib/disp encoding
            for (ULONG k = i + 2; k + 3 < Length && k < i + 5; k++) {
                if (*(PULONG)(&Instructions[k]) == 0x88) {
                    hasExportDirAccess = TRUE;
                    break;
                }
            }
        }

        //
        // Check for syscall stub pattern matching:
        // cmp byte [reg], 0x4C  followed by cmp byte [reg+X], 0xB8
        //
        if (Instructions[i] == 0x80 && i + 3 < Length) {
            if (Instructions[i + 2] == 0x4C) {
                for (ULONG j = i + 3; j < Length - 2 && j < i + 15; j++) {
                    if (Instructions[j] == 0x80 && j + 2 < Length &&
                        Instructions[j + 2] == 0xB8) {
                        hasSyscallStubRead = TRUE;
                        break;
                    }
                }
            }
        }
    }

    //
    // Strong signal: PE header check + export directory access
    //
    if (hasPeHeaderCheck && hasExportDirAccess) {
        if (Detection != NULL) {
            Detection->HasDynamicSsnResolution = TRUE;
        }
        return TRUE;
    }

    //
    // Medium signal: PE header check + syscall stub reading
    //
    if (hasPeHeaderCheck && hasSyscallStubRead) {
        if (Detection != NULL) {
            Detection->HasDynamicSsnResolution = TRUE;
        }
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Detect Halo's Gate: neighbor syscall walking.
 *
 * Requires BOTH a hook detection pattern (check for E9 jmp) AND
 * a 0x20-stride neighbor walk. Single indicators are too common in
 * legitimate code.
 */
static BOOLEAN
DsdpIsHalosGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length
)
{
    BOOLEAN hasHookCheck = FALSE;
    BOOLEAN hasStubStride = FALSE;
    BOOLEAN hasSsnAdjust = FALSE;

    if (Length < 25) {
        return FALSE;
    }

    for (ULONG i = 0; i < Length - 4; i++) {

        // Hook detection: cmp byte ptr [reg], 0xE9
        if (Instructions[i] == 0x80 && i + 3 < Length &&
            Instructions[i + 2] == DSD_JMP_REL32) {
            hasHookCheck = TRUE;
        }

        // 0x20 stride in pointer arithmetic (add/sub reg, 0x20)
        if (i + 3 < Length && Instructions[i] == 0x48 && Instructions[i + 1] == 0x83) {
            if (Instructions[i + 3] == 0x20) {
                hasStubStride = TRUE;
            }
        }

        // SSN adjustment: inc eax (FF C0), dec eax (FF C8),
        // add eax,imm8 (83 C0 XX), sub eax,imm8 (83 E8 XX)
        if (i + 2 < Length) {
            if (Instructions[i] == 0xFF &&
                (Instructions[i + 1] == 0xC0 || Instructions[i + 1] == 0xC8)) {
                hasSsnAdjust = TRUE;
            }
            if (Instructions[i] == 0x83 &&
                (Instructions[i + 1] == 0xC0 || Instructions[i + 1] == 0xE8)) {
                hasSsnAdjust = TRUE;
            }
        }
    }

    //
    // Require: hook detection + stub walking stride + SSN arithmetic
    // All three together strongly indicate Halo's Gate behavior.
    //
    return (hasHookCheck && hasStubStride && hasSsnAdjust);
}

/**
 * @brief Detect Tartarus Gate: exception-based SSN resolution.
 *
 * Requires BOTH an SEH frame setup (fs:[0] push/pop pattern) AND
 * an intentional exception trigger (int3, ud2). The old logic
 * matched ANY fs:/gs: prefix or ANY call instruction, which
 * matches virtually all x64 code. This version requires the
 * actual SEH frame setup sequence.
 */
static BOOLEAN
DsdpIsTartarusGatePattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length
)
{
    BOOLEAN hasSehFrameSetup = FALSE;
    BOOLEAN hasExceptionTrigger = FALSE;

    if (Length < 20) {
        return FALSE;
    }

    for (ULONG i = 0; i < Length - 4; i++) {

        //
        // SEH frame setup: push dword ptr fs:[0] => 64 FF 35 00 00 00 00
        // or mov eax, fs:[0] => 64 A1 00 00 00 00
        //
        if (Instructions[i] == 0x64) {  // fs: prefix
            if (i + 6 < Length &&
                Instructions[i + 1] == 0xFF && Instructions[i + 2] == 0x35 &&
                *(PULONG)(&Instructions[i + 3]) == 0) {
                hasSehFrameSetup = TRUE;
            }
            if (i + 5 < Length &&
                Instructions[i + 1] == 0xA1 &&
                *(PULONG)(&Instructions[i + 2]) == 0) {
                hasSehFrameSetup = TRUE;
            }
        }

        //
        // VEH: call to AddVectoredExceptionHandler is hard to detect
        // purely from bytes. Instead, look for RtlAddVectoredExceptionHandler
        // patterns: sub rsp, 28h; ... call rel32; ... with specific register setup.
        // This is imprecise but combined with exception trigger it's meaningful.
        //

        // int 3 (CC) — intentional breakpoint
        if (Instructions[i] == 0xCC) {
            hasExceptionTrigger = TRUE;
        }

        // ud2 (0F 0B) — intentional undefined instruction
        if (i + 1 < Length &&
            Instructions[i] == 0x0F && Instructions[i + 1] == 0x0B) {
            hasExceptionTrigger = TRUE;
        }

        // int 2d (CD 2D) — debug service exception
        if (i + 1 < Length &&
            Instructions[i] == 0xCD && Instructions[i + 1] == 0x2D) {
            hasExceptionTrigger = TRUE;
        }
    }

    return (hasSehFrameSetup && hasExceptionTrigger);
}

/**
 * @brief Detect SysWhispers v1/v2/v3 stub signatures.
 *
 * v2: Exact sequence: 4C 8B D1 B8 XX XX 00 00 0F 05 C3
 * v3: 4C 8B D1 B8 XX XX 00 00 ... 49 BB <imm64> 41 FF E3
 * v1: ror+xor hash loop pattern (requires tighter matching)
 */
static BOOLEAN
DsdpIsSysWhispersPattern(
    _In_reads_bytes_(Length) PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG Version
)
{
    *Version = 0;

    if (Length < 11) {
        return FALSE;
    }

    //
    // SysWhispers2: exact 11-byte stub
    // 4C 8B D1  B8 XX XX 00 00  0F 05  C3
    //
    for (ULONG i = 0; i + 10 < Length; i++) {
        if (Instructions[i + 0] == 0x4C &&
            Instructions[i + 1] == 0x8B &&
            Instructions[i + 2] == 0xD1 &&
            Instructions[i + 3] == 0xB8 &&
            Instructions[i + 6] == 0x00 &&
            Instructions[i + 7] == 0x00 &&
            Instructions[i + 8] == 0x0F &&
            Instructions[i + 9] == 0x05 &&
            Instructions[i + 10] == 0xC3) {

            // Sanity: SSN should be reasonable
            USHORT ssn = *(PUSHORT)(&Instructions[i + 4]);
            if (ssn < 0x2000) {
                *Version = 2;
                return TRUE;
            }
        }
    }

    //
    // SysWhispers3: 4C 8B D1 B8 XX XX 00 00 ... 49 BB <8 bytes> 41 FF E3
    //
    if (Length >= 21) {
        for (ULONG i = 0; i + 20 < Length; i++) {
            if (Instructions[i + 0] == 0x4C &&
                Instructions[i + 1] == 0x8B &&
                Instructions[i + 2] == 0xD1 &&
                Instructions[i + 3] == 0xB8 &&
                Instructions[i + 6] == 0x00 &&
                Instructions[i + 7] == 0x00) {

                for (ULONG j = i + 8; j + 12 < Length && j < i + 20; j++) {
                    if (Instructions[j] == 0x49 && Instructions[j + 1] == 0xBB &&
                        j + 12 < Length &&
                        Instructions[j + 10] == 0x41 &&
                        Instructions[j + 11] == 0xFF &&
                        Instructions[j + 12] == 0xE3) {
                        *Version = 3;
                        return TRUE;
                    }
                }
            }
        }
    }

    //
    // SysWhispers1: ror/rol + xor hash loop with specific structure.
    // Require: C1 [C8-CF] XX (ror reg, imm8) followed within 6 bytes by
    //          33 [C0-FF] (xor reg, reg) — tighter than just any C1/33.
    //
    if (Length >= 10) {
        for (ULONG i = 0; i + 6 < Length; i++) {
            if (Instructions[i] == 0xC1 &&
                (Instructions[i + 1] >= 0xC8 && Instructions[i + 1] <= 0xCF)) {
                // ror reg, imm8 found; look for xor within 6 bytes
                for (ULONG j = i + 3; j + 1 < Length && j < i + 9; j++) {
                    if (Instructions[j] == 0x33 &&
                        (Instructions[j + 1] >= 0xC0 && Instructions[j + 1] <= 0xFF)) {
                        *Version = 1;
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - WHITELIST
// ============================================================================

static BOOLEAN
DsdpIsWhitelisted(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_opt_ PCWSTR ModuleName
)
{
    PLIST_ENTRY entry;
    PDSD_WHITELIST_ENTRY whitelist;
    ULONG_PTR addr = (ULONG_PTR)Address;
    BOOLEAN found = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->Base.WhitelistLock);

    for (entry = Detector->Base.WhitelistPatterns.Flink;
         entry != &Detector->Base.WhitelistPatterns;
         entry = entry->Flink) {

        whitelist = CONTAINING_RECORD(entry, DSD_WHITELIST_ENTRY, ListEntry);

        if (whitelist->MatchByAddress) {
            if (addr >= whitelist->BaseAddress &&
                addr < (whitelist->BaseAddress + whitelist->Size)) {
                found = TRUE;
                break;
            }
        }

        if (whitelist->MatchByName && ModuleName != NULL) {
            UNICODE_STRING candidate;
            RtlInitUnicodeString(&candidate, ModuleName);
            if (RtlEqualUnicodeString(&whitelist->ModuleName, &candidate, TRUE)) {
                found = TRUE;
                break;
            }
        }
    }

    ExReleasePushLockShared(&Detector->Base.WhitelistLock);
    KeLeaveCriticalRegion();

    return found;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - SCORING
// ============================================================================

static ULONG
DsdpCalculateSuspicionScore(
    _In_ PDSD_DETECTION_INTERNAL Detection
)
{
    ULONG score = 0;

    //
    // Base score by technique (mutually exclusive — no double-counting)
    //
    switch (Detection->Base.Technique) {
        case DsdTechnique_DirectSyscall:  score = 80;  break;
        case DsdTechnique_IndirectSyscall: score = 60; break;
        case DsdTechnique_HeavensGate:    score = 95;  break;
        case DsdTechnique_HellsGate:      score = 90;  break;
        case DsdTechnique_HalosGate:      score = 85;  break;
        case DsdTechnique_TartarusGate:   score = 90;  break;
        case DsdTechnique_SysWhispers:    score = 85;  break;
        case DsdTechnique_Manual:         score = 70;  break;
        default: break;
    }

    //
    // Contextual adjustments (additive, capped)
    //
    if (!Detection->Base.CallFromNtdll) {
        score += 10;
    }

    if (!Detection->Base.CallFromKnownModule) {
        score += 20;
    }

    if (!Detection->HasReturnToNtdll && Detection->Base.ReturnAddressCount > 0) {
        score += 5;
    }

    if (score > 100) {
        score = 100;
    }

    return score;
}

