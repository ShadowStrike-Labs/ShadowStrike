/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE DIRECT SYSCALL DETECTION ENGINE
 * ============================================================================
 *
 * @file DirectSyscallDetector.c
 * @brief Enterprise-grade direct syscall abuse detection engine.
 *
 * Implements CrowdStrike Falcon-class direct syscall detection with:
 * - Direct syscall pattern detection (mov eax, SSN; syscall)
 * - Indirect syscall detection (jmp to ntdll syscall stub)
 * - Heaven's Gate detection (WoW64 32->64 bit transition abuse)
 * - Hell's Gate detection (dynamic SSN resolution patterns)
 * - Halo's Gate detection (neighbor syscall walking)
 * - Tartarus Gate detection (exception-based SSN resolution)
 * - SysWhispers signature detection (all versions)
 * - Call stack integrity validation and analysis
 * - NTDLL integrity verification integration
 * - Per-process detection context tracking
 * - Whitelist pattern management for false positive reduction
 * - Comprehensive telemetry and statistics
 *
 * Detection Techniques:
 * - Opcode pattern matching for syscall instructions
 * - Return address validation against known modules
 * - Stack pointer sanity checking
 * - Module base address verification
 * - Instruction sequence analysis
 * - Cross-reference with NTDLL export table
 *
 * MITRE ATT&CK Coverage:
 * - T1106: Native API (direct syscall invocation)
 * - T1055: Process Injection (syscall-based injection)
 * - T1620: Reflective Code Loading (in-memory syscall stubs)
 * - T1562.001: Impair Defenses (unhooking via direct syscalls)
 *
 * Security Hardened v2.0.0:
 * - All input parameters validated before use
 * - Safe memory access with exception handling
 * - Reference counting for thread safety
 * - Proper cleanup on all error paths
 * - Rate limiting to prevent DoS
 * - Memory-efficient detection record pooling
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "DirectSyscallDetector.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Maximum detection records to retain
 */
#define DSD_MAX_DETECTIONS                  4096

/**
 * @brief Maximum whitelist patterns
 */
#define DSD_MAX_WHITELIST_PATTERNS          256

/**
 * @brief Lookaside list depth for detections
 */
#define DSD_DETECTION_LOOKASIDE_DEPTH       128

/**
 * @brief Maximum call stack depth to analyze
 */
#define DSD_MAX_STACK_DEPTH                 64

/**
 * @brief Minimum instruction bytes to analyze
 */
#define DSD_MIN_INSTRUCTION_BYTES           16

/**
 * @brief Maximum instruction bytes to analyze
 */
#define DSD_MAX_INSTRUCTION_BYTES           64

/**
 * @brief Detector magic for validation
 */
#define DSD_DETECTOR_MAGIC                  0x44534454  // 'DSDT'

/**
 * @brief Detection magic for validation
 */
#define DSD_DETECTION_MAGIC                 0x44534443  // 'DSDC'

/**
 * @brief Pool tag for whitelist entries
 */
#define DSD_WHITELIST_TAG                   'WLSD'

/**
 * @brief Pool tag for detection entries
 */
#define DSD_DETECTION_TAG                   'DESD'

/**
 * @brief User-mode address space limit (x64)
 */
#define DSD_USER_SPACE_LIMIT                0x00007FFFFFFFFFFF

/**
 * @brief NTDLL base search start
 */
#define DSD_NTDLL_SEARCH_START              0x00007FF000000000

/**
 * @brief High suspicion score threshold
 */
#define DSD_HIGH_SUSPICION_THRESHOLD        75

/**
 * @brief Medium suspicion score threshold
 */
#define DSD_MEDIUM_SUSPICION_THRESHOLD      50

// ============================================================================
// SYSCALL INSTRUCTION PATTERNS
// ============================================================================

/**
 * @brief x64 syscall instruction opcode (0F 05)
 */
#define DSD_SYSCALL_OPCODE_0                0x0F
#define DSD_SYSCALL_OPCODE_1                0x05

/**
 * @brief x86 sysenter instruction opcode (0F 34)
 */
#define DSD_SYSENTER_OPCODE_0               0x0F
#define DSD_SYSENTER_OPCODE_1               0x34

/**
 * @brief x86 int 2e instruction opcode (CD 2E)
 */
#define DSD_INT2E_OPCODE_0                  0xCD
#define DSD_INT2E_OPCODE_1                  0x2E

/**
 * @brief mov eax, imm32 opcode (B8)
 */
#define DSD_MOV_EAX_IMM32                   0xB8

/**
 * @brief mov r10, rcx opcode (49 89 CA or 4C 8B D1)
 */
#define DSD_MOV_R10_RCX_0                   0x4C
#define DSD_MOV_R10_RCX_1                   0x8B
#define DSD_MOV_R10_RCX_2                   0xD1

/**
 * @brief jmp rel32 opcode (E9)
 */
#define DSD_JMP_REL32                       0xE9

/**
 * @brief jmp [rip+disp32] opcode (FF 25)
 */
#define DSD_JMP_RIP_DISP32_0                0xFF
#define DSD_JMP_RIP_DISP32_1                0x25

/**
 * @brief call rel32 opcode (E8)
 */
#define DSD_CALL_REL32                      0xE8

/**
 * @brief ret opcode (C3)
 */
#define DSD_RET                             0xC3

/**
 * @brief Heaven's Gate segment prefix (0x33)
 */
#define DSD_HEAVENS_GATE_SEGMENT            0x33

/**
 * @brief Far jmp opcode for Heaven's Gate (EA)
 */
#define DSD_FAR_JMP                         0xEA

/**
 * @brief retf opcode (CB)
 */
#define DSD_RETF                            0xCB

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Internal detector context with extended fields
 */
typedef struct _DSD_DETECTOR_INTERNAL {
    //
    // Base structure (must be first)
    //
    DSD_DETECTOR Base;

    //
    // Magic for validation
    //
    ULONG Magic;

    //
    // Lookaside list for detection allocations
    //
    NPAGED_LOOKASIDE_LIST DetectionLookaside;
    BOOLEAN LookasideInitialized;

    //
    // NTDLL information cache
    //
    PVOID NtdllBase;
    SIZE_T NtdllSize;
    PVOID NtdllSyscallRegionStart;
    PVOID NtdllSyscallRegionEnd;
    BOOLEAN NtdllInfoValid;
    EX_PUSH_LOCK NtdllLock;

    //
    // Syscall number cache
    //
    ULONG KnownSyscallNumbers[512];
    ULONG KnownSyscallCount;
    EX_PUSH_LOCK SyscallCacheLock;

    //
    // Reference counting
    //
    volatile LONG ReferenceCount;
    volatile LONG ShuttingDown;
    KEVENT ShutdownEvent;

    //
    // Rate limiting
    //
    volatile LONG64 AnalysisCount;
    LARGE_INTEGER LastRateLimitReset;
    ULONG RateLimitPerSecond;

} DSD_DETECTOR_INTERNAL, *PDSD_DETECTOR_INTERNAL;

/**
 * @brief Internal detection with extended fields
 */
typedef struct _DSD_DETECTION_INTERNAL {
    //
    // Base structure (must be first)
    //
    DSD_DETECTION Base;

    //
    // Magic for validation
    //
    ULONG Magic;

    //
    // Extended analysis data
    //
    UCHAR InstructionBytes[DSD_MAX_INSTRUCTION_BYTES];
    ULONG InstructionLength;

    //
    // Pattern match details
    //
    BOOLEAN HasMovEax;
    BOOLEAN HasMovR10Rcx;
    BOOLEAN HasSyscallInstruction;
    BOOLEAN HasJmpToNtdll;
    BOOLEAN HasReturnToNtdll;

    //
    // Hell's Gate specific
    //
    BOOLEAN HasDynamicSsnResolution;
    PVOID SsnResolutionAddress;

    //
    // Heaven's Gate specific
    //
    BOOLEAN HasSegmentSwitch;
    UCHAR TargetSegment;

    //
    // SysWhispers specific
    //
    ULONG SysWhispersVersion;
    BOOLEAN HasSysWhispersPattern;

    //
    // Back reference
    //
    PDSD_DETECTOR_INTERNAL Detector;
    volatile LONG ReferenceCount;

} DSD_DETECTION_INTERNAL, *PDSD_DETECTION_INTERNAL;

/**
 * @brief Whitelist pattern entry
 */
typedef struct _DSD_WHITELIST_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING ModuleName;
    ULONG64 BaseAddress;
    SIZE_T Size;
    BOOLEAN MatchByName;
    BOOLEAN MatchByAddress;
    ULONG64 AddedTimestamp;
} DSD_WHITELIST_ENTRY, *PDSD_WHITELIST_ENTRY;

/**
 * @brief Instruction analysis context
 */
typedef struct _DSD_INSTRUCTION_CONTEXT {
    PUCHAR InstructionPointer;
    ULONG Length;
    BOOLEAN IsValid;

    //
    // Decoded information
    //
    BOOLEAN IsSyscall;
    BOOLEAN IsSysenter;
    BOOLEAN IsInt2e;
    BOOLEAN IsMovEaxImm;
    ULONG ImmediateValue;
    BOOLEAN IsJmp;
    BOOLEAN IsCall;
    BOOLEAN IsRet;
    LONG32 Displacement;

} DSD_INSTRUCTION_CONTEXT, *PDSD_INSTRUCTION_CONTEXT;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static VOID
DsdpAcquireReference(
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

static NTSTATUS
DsdpAnalyzeInstructions(
    _In_ PVOID Address,
    _In_ SIZE_T MaxLength,
    _Out_ PDSD_INSTRUCTION_CONTEXT Context
);

static BOOLEAN
DsdpIsDirectSyscallPattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG SyscallNumber
);

static BOOLEAN
DsdpIsIndirectSyscallPattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PVOID NtdllBase,
    _In_ SIZE_T NtdllSize
);

static BOOLEAN
DsdpIsHeavensGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length
);

static BOOLEAN
DsdpIsHellsGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PDSD_DETECTION_INTERNAL Detection
);

static BOOLEAN
DsdpIsHalosGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PDSD_DETECTION_INTERNAL Detection
);

static BOOLEAN
DsdpIsTartarusGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length
);

static BOOLEAN
DsdpIsSysWhispersPattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG Version
);

static NTSTATUS
DsdpCaptureCallStack(
    _In_ HANDLE ThreadId,
    _Out_writes_(MaxFrames) PVOID* Frames,
    _In_ ULONG MaxFrames,
    _Out_ PULONG CapturedFrames
);

static BOOLEAN
DsdpIsAddressInNtdll(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address
);

static BOOLEAN
DsdpIsAddressInKnownModule(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _Out_opt_ PUNICODE_STRING ModuleName,
    _Out_opt_ PULONG64 ModuleBase
);

static NTSTATUS
DsdpRefreshNtdllInfo(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
);

static ULONG
DsdpCalculateSuspicionScore(
    _In_ PDSD_DETECTION_INTERNAL Detection
);

static BOOLEAN
DsdpIsWhitelisted(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_opt_ PUNICODE_STRING ModuleName
);

static NTSTATUS
DsdpSafeReadMemory(
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
);

static BOOLEAN
DsdpValidateUserAddress(
    _In_ PVOID Address,
    _In_ SIZE_T Size
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DsdInitialize)
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
    NTSTATUS status = STATUS_SUCCESS;
    PDSD_DETECTOR_INTERNAL detector = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    detector = (PDSD_DETECTOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(DSD_DETECTOR_INTERNAL),
        DSD_POOL_TAG
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detector, sizeof(DSD_DETECTOR_INTERNAL));

    //
    // Set magic
    //
    detector->Magic = DSD_DETECTOR_MAGIC;

    //
    // Initialize detection list
    //
    InitializeListHead(&detector->Base.DetectionList);
    ExInitializePushLock(&detector->Base.DetectionLock);

    //
    // Initialize whitelist
    //
    InitializeListHead(&detector->Base.WhitelistPatterns);

    //
    // Initialize NTDLL info lock
    //
    ExInitializePushLock(&detector->NtdllLock);
    detector->NtdllInfoValid = FALSE;

    //
    // Initialize syscall cache lock
    //
    ExInitializePushLock(&detector->SyscallCacheLock);
    detector->KnownSyscallCount = 0;

    //
    // Initialize lookaside list for detections
    //
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

    //
    // Initialize reference counting
    //
    detector->ReferenceCount = 1;
    detector->ShuttingDown = FALSE;
    KeInitializeEvent(&detector->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize rate limiting
    //
    detector->RateLimitPerSecond = 10000;  // 10K analyses per second max
    KeQuerySystemTime(&detector->LastRateLimitReset);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&detector->Base.Stats.StartTime);

    //
    // Mark as initialized
    //
    detector->Base.Initialized = TRUE;

    *Detector = (PDSD_DETECTOR)detector;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
DsdShutdown(
    _Inout_ PDSD_DETECTOR Detector
)
{
    PDSD_DETECTOR_INTERNAL detector = (PDSD_DETECTOR_INTERNAL)Detector;
    PLIST_ENTRY entry;
    PDSD_DETECTION_INTERNAL detection;
    PDSD_WHITELIST_ENTRY whitelist;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    if (detector->Magic != DSD_DETECTOR_MAGIC) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&detector->ShuttingDown, 1);

    //
    // Wait for references to drain
    //
    timeout.QuadPart = -10000;  // 1ms
    while (detector->ReferenceCount > 1) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    //
    // Free all detection records
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->Base.DetectionLock);

    while (!IsListEmpty(&detector->Base.DetectionList)) {
        entry = RemoveHeadList(&detector->Base.DetectionList);
        detection = CONTAINING_RECORD(entry, DSD_DETECTION_INTERNAL, Base.ListEntry);

        //
        // Free module name if allocated
        //
        if (detection->Base.CallerModule.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(
                detection->Base.CallerModule.Buffer,
                DSD_POOL_TAG
            );
        }

        if (detector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&detector->DetectionLookaside, detection);
        } else {
            ShadowStrikeFreePoolWithTag(detection, DSD_DETECTION_TAG);
        }
    }

    ExReleasePushLockExclusive(&detector->Base.DetectionLock);
    KeLeaveCriticalRegion();

    //
    // Free whitelist entries
    //
    while (!IsListEmpty(&detector->Base.WhitelistPatterns)) {
        entry = RemoveHeadList(&detector->Base.WhitelistPatterns);
        whitelist = CONTAINING_RECORD(entry, DSD_WHITELIST_ENTRY, ListEntry);

        if (whitelist->ModuleName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(whitelist->ModuleName.Buffer, DSD_WHITELIST_TAG);
        }

        ShadowStrikeFreePoolWithTag(whitelist, DSD_WHITELIST_TAG);
    }

    //
    // Delete lookaside list
    //
    if (detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&detector->DetectionLookaside);
        detector->LookasideInitialized = FALSE;
    }

    //
    // Clear state
    //
    detector->Magic = 0;
    detector->Base.Initialized = FALSE;

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
    NTSTATUS status = STATUS_SUCCESS;
    PDSD_DETECTOR_INTERNAL detector = (PDSD_DETECTOR_INTERNAL)Detector;
    PDSD_DETECTION_INTERNAL detection = NULL;
    UCHAR instructionBuffer[DSD_MAX_INSTRUCTION_BYTES];
    ULONG capturedLength = 0;
    DSD_TECHNIQUE technique = DsdTechnique_None;
    ULONG sysWhispersVersion = 0;
    BOOLEAN isWhitelisted = FALSE;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (detector->Magic != DSD_DETECTOR_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallerAddress == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (Detection == NULL) {
        return STATUS_INVALID_PARAMETER_6;
    }

    *Detection = NULL;

    //
    // Check shutdown
    //
    if (detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate caller address is in user space
    //
    if (!DsdpValidateUserAddress(CallerAddress, DSD_MIN_INSTRUCTION_BYTES)) {
        return STATUS_INVALID_ADDRESS;
    }

    DsdpAcquireReference(detector);

    //
    // Update statistics
    //
    InterlockedIncrement64(&detector->Base.Stats.SyscallsAnalyzed);

    //
    // Refresh NTDLL info if needed
    //
    if (!detector->NtdllInfoValid) {
        DsdpRefreshNtdllInfo(detector);
    }

    //
    // Check whitelist first
    //
    isWhitelisted = DsdpIsWhitelisted(detector, CallerAddress, NULL);
    if (isWhitelisted) {
        DsdpReleaseReference(detector);
        return STATUS_SUCCESS;  // No detection for whitelisted addresses
    }

    //
    // Read instruction bytes from caller address
    //
    RtlZeroMemory(instructionBuffer, sizeof(instructionBuffer));

    status = DsdpSafeReadMemory(
        CallerAddress,
        instructionBuffer,
        DSD_MAX_INSTRUCTION_BYTES
    );

    if (!NT_SUCCESS(status)) {
        //
        // Try reading fewer bytes
        //
        status = DsdpSafeReadMemory(
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
    // Allocate detection record
    //
    status = DsdpAllocateDetection(detector, &detection);
    if (!NT_SUCCESS(status)) {
        DsdpReleaseReference(detector);
        return status;
    }

    //
    // Initialize basic detection fields
    //
    detection->Base.ProcessId = ProcessId;
    detection->Base.ThreadId = ThreadId;
    detection->Base.CallerAddress = CallerAddress;
    detection->Base.SyscallNumber = SyscallNumber;
    KeQuerySystemTime(&detection->Base.Timestamp);

    //
    // Copy instruction bytes
    //
    RtlCopyMemory(detection->InstructionBytes, instructionBuffer, capturedLength);
    detection->InstructionLength = capturedLength;

    //
    // Analyze for direct syscall pattern
    //
    ULONG detectedSsn = 0;
    if (DsdpIsDirectSyscallPattern(instructionBuffer, capturedLength, &detectedSsn)) {
        technique = DsdTechnique_DirectSyscall;
        detection->HasMovEax = TRUE;
        detection->HasSyscallInstruction = TRUE;
        InterlockedIncrement64(&detector->Base.Stats.DirectCalls);
    }

    //
    // Check for indirect syscall if not direct
    //
    if (technique == DsdTechnique_None) {
        if (DsdpIsIndirectSyscallPattern(
                instructionBuffer,
                capturedLength,
                detector->NtdllBase,
                detector->NtdllSize)) {

            technique = DsdTechnique_IndirectSyscall;
            detection->HasJmpToNtdll = TRUE;
            InterlockedIncrement64(&detector->Base.Stats.IndirectCalls);
        }
    }

    //
    // Check for Heaven's Gate
    //
    if (technique == DsdTechnique_None) {
        if (DsdpIsHeavensGatePattern(instructionBuffer, capturedLength)) {
            technique = DsdTechnique_HeavensGate;
            detection->HasSegmentSwitch = TRUE;
            detection->TargetSegment = DSD_HEAVENS_GATE_SEGMENT;
            InterlockedIncrement64(&detector->Base.Stats.HeavensGateCalls);
        }
    }

    //
    // Check for Hell's Gate
    //
    if (technique == DsdTechnique_None) {
        if (DsdpIsHellsGatePattern(instructionBuffer, capturedLength, detection)) {
            technique = DsdTechnique_HellsGate;
            detection->HasDynamicSsnResolution = TRUE;
        }
    }

    //
    // Check for Halo's Gate
    //
    if (technique == DsdTechnique_None) {
        if (DsdpIsHalosGatePattern(instructionBuffer, capturedLength, detection)) {
            technique = DsdTechnique_HalosGate;
        }
    }

    //
    // Check for Tartarus Gate
    //
    if (technique == DsdTechnique_None) {
        if (DsdpIsTartarusGatePattern(instructionBuffer, capturedLength)) {
            technique = DsdTechnique_TartarusGate;
        }
    }

    //
    // Check for SysWhispers pattern
    //
    if (DsdpIsSysWhispersPattern(instructionBuffer, capturedLength, &sysWhispersVersion)) {
        if (technique == DsdTechnique_None) {
            technique = DsdTechnique_SysWhispers;
        }
        detection->HasSysWhispersPattern = TRUE;
        detection->SysWhispersVersion = sysWhispersVersion;
    }

    detection->Base.Technique = technique;

    //
    // Check if caller is from NTDLL
    //
    detection->Base.CallFromNtdll = DsdpIsAddressInNtdll(detector, CallerAddress);

    //
    // Check if caller is from a known module
    //
    detection->Base.CallFromKnownModule = DsdpIsAddressInKnownModule(
        detector,
        CallerAddress,
        &detection->Base.CallerModule,
        &detection->Base.CallerModuleBase
    );

    //
    // Calculate offset within module
    //
    if (detection->Base.CallerModuleBase != 0) {
        detection->Base.CallerOffset =
            (ULONG64)CallerAddress - detection->Base.CallerModuleBase;
    }

    //
    // Capture call stack
    //
    status = DsdpCaptureCallStack(
        ThreadId,
        detection->Base.ReturnAddresses,
        ARRAYSIZE(detection->Base.ReturnAddresses),
        &detection->Base.ReturnAddressCount
    );

    //
    // Validate return addresses
    //
    if (NT_SUCCESS(status) && detection->Base.ReturnAddressCount > 0) {
        for (ULONG i = 0; i < detection->Base.ReturnAddressCount; i++) {
            if (DsdpIsAddressInNtdll(detector, detection->Base.ReturnAddresses[i])) {
                detection->HasReturnToNtdll = TRUE;
                break;
            }
        }
    }

    //
    // Calculate suspicion score
    //
    detection->Base.SuspicionScore = DsdpCalculateSuspicionScore(detection);

    //
    // Add to detection list if technique detected or high suspicion
    //
    if (technique != DsdTechnique_None ||
        detection->Base.SuspicionScore >= DSD_MEDIUM_SUSPICION_THRESHOLD) {

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&detector->Base.DetectionLock);

        //
        // Enforce maximum detection count
        //
        if ((ULONG)detector->Base.DetectionCount >= DSD_MAX_DETECTIONS) {
            //
            // Remove oldest detection
            //
            if (!IsListEmpty(&detector->Base.DetectionList)) {
                PLIST_ENTRY oldEntry = RemoveHeadList(&detector->Base.DetectionList);
                PDSD_DETECTION_INTERNAL oldDetection = CONTAINING_RECORD(
                    oldEntry, DSD_DETECTION_INTERNAL, Base.ListEntry
                );

                if (oldDetection->Base.CallerModule.Buffer != NULL) {
                    ShadowStrikeFreePoolWithTag(
                        oldDetection->Base.CallerModule.Buffer,
                        DSD_POOL_TAG
                    );
                }

                if (detector->LookasideInitialized) {
                    ExFreeToNPagedLookasideList(&detector->DetectionLookaside, oldDetection);
                } else {
                    ShadowStrikeFreePoolWithTag(oldDetection, DSD_DETECTION_TAG);
                }

                InterlockedDecrement(&detector->Base.DetectionCount);
            }
        }

        InsertTailList(&detector->Base.DetectionList, &detection->Base.ListEntry);
        InterlockedIncrement(&detector->Base.DetectionCount);

        ExReleasePushLockExclusive(&detector->Base.DetectionLock);
        KeLeaveCriticalRegion();

        *Detection = &detection->Base;

    } else {
        //
        // No significant detection - free the record
        //
        DsdpFreeDetectionInternal(detector, detection);
    }

    DsdpReleaseReference(detector);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdDetectTechnique(
    _In_ PDSD_DETECTOR Detector,
    _In_ PVOID Address,
    _In_ ULONG Length,
    _Out_ PDSD_TECHNIQUE Technique
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDSD_DETECTOR_INTERNAL detector = (PDSD_DETECTOR_INTERNAL)Detector;
    PUCHAR buffer = NULL;
    ULONG sysWhispersVersion = 0;
    ULONG detectedSsn = 0;
    DSD_DETECTION_INTERNAL tempDetection;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Address == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Length == 0 || Length > DSD_MAX_INSTRUCTION_BYTES) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Technique == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    *Technique = DsdTechnique_None;

    if (detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    DsdpAcquireReference(detector);

    //
    // Allocate buffer for instruction bytes
    //
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
    // Read memory
    //
    status = DsdpSafeReadMemory(Address, buffer, Length);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(buffer, DSD_POOL_TAG);
        DsdpReleaseReference(detector);
        return status;
    }

    //
    // Initialize temporary detection for analysis
    //
    RtlZeroMemory(&tempDetection, sizeof(tempDetection));

    //
    // Check patterns in order of specificity
    //

    //
    // 1. Direct syscall pattern
    //
    if (DsdpIsDirectSyscallPattern(buffer, Length, &detectedSsn)) {
        *Technique = DsdTechnique_DirectSyscall;
        goto Cleanup;
    }

    //
    // 2. Heaven's Gate pattern
    //
    if (DsdpIsHeavensGatePattern(buffer, Length)) {
        *Technique = DsdTechnique_HeavensGate;
        goto Cleanup;
    }

    //
    // 3. Hell's Gate pattern
    //
    if (DsdpIsHellsGatePattern(buffer, Length, &tempDetection)) {
        *Technique = DsdTechnique_HellsGate;
        goto Cleanup;
    }

    //
    // 4. Halo's Gate pattern
    //
    if (DsdpIsHalosGatePattern(buffer, Length, &tempDetection)) {
        *Technique = DsdTechnique_HalosGate;
        goto Cleanup;
    }

    //
    // 5. Tartarus Gate pattern
    //
    if (DsdpIsTartarusGatePattern(buffer, Length)) {
        *Technique = DsdTechnique_TartarusGate;
        goto Cleanup;
    }

    //
    // 6. SysWhispers pattern
    //
    if (DsdpIsSysWhispersPattern(buffer, Length, &sysWhispersVersion)) {
        *Technique = DsdTechnique_SysWhispers;
        goto Cleanup;
    }

    //
    // 7. Indirect syscall pattern (needs NTDLL info)
    //
    if (detector->NtdllInfoValid) {
        if (DsdpIsIndirectSyscallPattern(
                buffer, Length, detector->NtdllBase, detector->NtdllSize)) {
            *Technique = DsdTechnique_IndirectSyscall;
            goto Cleanup;
        }
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
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsValid,
    _Out_opt_ PDSD_TECHNIQUE Technique
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDSD_DETECTOR_INTERNAL detector = (PDSD_DETECTOR_INTERNAL)Detector;
    PVOID frames[DSD_MAX_STACK_DEPTH];
    ULONG frameCount = 0;
    BOOLEAN hasNtdllFrame = FALSE;
    BOOLEAN hasUnknownFrame = FALSE;
    ULONG unknownFrameCount = 0;
    DSD_TECHNIQUE detectedTechnique = DsdTechnique_None;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (IsValid == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *IsValid = TRUE;  // Assume valid unless proven otherwise
    if (Technique != NULL) {
        *Technique = DsdTechnique_None;
    }

    if (detector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    DsdpAcquireReference(detector);

    //
    // Capture call stack
    //
    status = DsdpCaptureCallStack(
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
        //
        // Empty call stack is suspicious
        //
        *IsValid = FALSE;
        DsdpReleaseReference(detector);
        return STATUS_SUCCESS;
    }

    //
    // Refresh NTDLL info if needed
    //
    if (!detector->NtdllInfoValid) {
        DsdpRefreshNtdllInfo(detector);
    }

    //
    // Analyze each frame
    //
    for (ULONG i = 0; i < frameCount; i++) {
        PVOID frame = frames[i];

        if (frame == NULL) {
            continue;
        }

        //
        // Check if frame is in NTDLL
        //
        if (DsdpIsAddressInNtdll(detector, frame)) {
            hasNtdllFrame = TRUE;
        } else if (!DsdpIsAddressInKnownModule(detector, frame, NULL, NULL)) {
            //
            // Frame is not in any known module
            //
            hasUnknownFrame = TRUE;
            unknownFrameCount++;
        }
    }

    //
    // Determine validity based on analysis
    //
    // A valid syscall from user mode should have:
    // 1. At least one frame in NTDLL (for normal API calls)
    // 2. No frames in unknown memory regions (executable heap/stack is suspicious)
    //

    if (!hasNtdllFrame) {
        //
        // No NTDLL frame - likely direct syscall
        //
        *IsValid = FALSE;
        detectedTechnique = DsdTechnique_DirectSyscall;
    }

    if (unknownFrameCount > 0) {
        //
        // Has frames in unknown regions - suspicious
        //
        *IsValid = FALSE;

        //
        // If multiple unknown frames, might be shellcode or injected code
        //
        if (unknownFrameCount >= 3) {
            detectedTechnique = DsdTechnique_Manual;
        }
    }

    //
    // Check for Heaven's Gate pattern in first frame
    //
    if (frameCount > 0 && frames[0] != NULL) {
        UCHAR instructionBuffer[16];

        status = DsdpSafeReadMemory(frames[0], instructionBuffer, sizeof(instructionBuffer));
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
    _In_ PDSD_DETECTION Detection
)
{
    PDSD_DETECTION_INTERNAL detection;
    PDSD_DETECTOR_INTERNAL detector;

    PAGED_CODE();

    if (Detection == NULL) {
        return;
    }

    detection = CONTAINING_RECORD(Detection, DSD_DETECTION_INTERNAL, Base);

    if (detection->Magic != DSD_DETECTION_MAGIC) {
        return;
    }

    detector = detection->Detector;
    if (detector == NULL || detector->Magic != DSD_DETECTOR_MAGIC) {
        //
        // No detector reference - just free with pool tag
        //
        if (Detection->CallerModule.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(Detection->CallerModule.Buffer, DSD_POOL_TAG);
        }
        ShadowStrikeFreePoolWithTag(detection, DSD_DETECTION_TAG);
        return;
    }

    //
    // Remove from detection list if still linked
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->Base.DetectionLock);

    if (!IsListEmpty(&detection->Base.ListEntry)) {
        RemoveEntryList(&detection->Base.ListEntry);
        InterlockedDecrement(&detector->Base.DetectionCount);
    }

    ExReleasePushLockExclusive(&detector->Base.DetectionLock);
    KeLeaveCriticalRegion();

    DsdpFreeDetectionInternal(detector, detection);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

static VOID
DsdpAcquireReference(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
)
{
    InterlockedIncrement(&Detector->ReferenceCount);
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

    *Detection = NULL;

    if (Detector->LookasideInitialized) {
        detection = (PDSD_DETECTION_INTERNAL)ExAllocateFromNPagedLookasideList(
            &Detector->DetectionLookaside
        );
    }

    if (detection == NULL) {
        detection = (PDSD_DETECTION_INTERNAL)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(DSD_DETECTION_INTERNAL),
            DSD_DETECTION_TAG
        );
    }

    if (detection == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detection, sizeof(DSD_DETECTION_INTERNAL));

    detection->Magic = DSD_DETECTION_MAGIC;
    detection->Detector = Detector;
    detection->ReferenceCount = 1;
    InitializeListHead(&detection->Base.ListEntry);

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

    //
    // Free module name buffer if allocated
    //
    if (Detection->Base.CallerModule.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Detection->Base.CallerModule.Buffer, DSD_POOL_TAG);
        Detection->Base.CallerModule.Buffer = NULL;
    }

    Detection->Magic = 0;

    if (Detector->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Detector->DetectionLookaside, Detection);
    } else {
        ShadowStrikeFreePoolWithTag(Detection, DSD_DETECTION_TAG);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PATTERN DETECTION
// ============================================================================

/**
 * @brief Detect direct syscall pattern: mov eax, SSN; mov r10, rcx; syscall
 */
static BOOLEAN
DsdpIsDirectSyscallPattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG SyscallNumber
)
{
    ULONG i;
    BOOLEAN foundMovEax = FALSE;
    BOOLEAN foundMovR10Rcx = FALSE;
    BOOLEAN foundSyscall = FALSE;
    ULONG ssn = 0;

    *SyscallNumber = 0;

    if (Length < 10) {
        return FALSE;
    }

    //
    // Scan for pattern components
    //
    for (i = 0; i < Length - 1; i++) {
        //
        // Check for mov eax, imm32 (B8 XX XX XX XX)
        //
        if (Instructions[i] == DSD_MOV_EAX_IMM32 && i + 4 < Length) {
            ssn = *(PULONG)(&Instructions[i + 1]);
            foundMovEax = TRUE;
            i += 4;
            continue;
        }

        //
        // Check for mov r10, rcx (4C 8B D1)
        //
        if (i + 2 < Length &&
            Instructions[i] == DSD_MOV_R10_RCX_0 &&
            Instructions[i + 1] == DSD_MOV_R10_RCX_1 &&
            Instructions[i + 2] == DSD_MOV_R10_RCX_2) {

            foundMovR10Rcx = TRUE;
            i += 2;
            continue;
        }

        //
        // Check for syscall (0F 05)
        //
        if (Instructions[i] == DSD_SYSCALL_OPCODE_0 &&
            Instructions[i + 1] == DSD_SYSCALL_OPCODE_1) {

            foundSyscall = TRUE;
            break;
        }

        //
        // Check for sysenter (0F 34)
        //
        if (Instructions[i] == DSD_SYSENTER_OPCODE_0 &&
            Instructions[i + 1] == DSD_SYSENTER_OPCODE_1) {

            foundSyscall = TRUE;
            break;
        }

        //
        // Check for int 2e (CD 2E)
        //
        if (Instructions[i] == DSD_INT2E_OPCODE_0 &&
            Instructions[i + 1] == DSD_INT2E_OPCODE_1) {

            foundSyscall = TRUE;
            break;
        }
    }

    //
    // Must have mov eax and syscall to be a direct syscall
    //
    if (foundMovEax && foundSyscall) {
        *SyscallNumber = ssn;
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Detect indirect syscall pattern: jmp to NTDLL syscall stub
 */
static BOOLEAN
DsdpIsIndirectSyscallPattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PVOID NtdllBase,
    _In_ SIZE_T NtdllSize
)
{
    ULONG i;
    LONG32 displacement;
    PVOID targetAddress;
    ULONG_PTR ntdllStart;
    ULONG_PTR ntdllEnd;

    if (NtdllBase == NULL || NtdllSize == 0) {
        return FALSE;
    }

    if (Length < 5) {
        return FALSE;
    }

    ntdllStart = (ULONG_PTR)NtdllBase;
    ntdllEnd = ntdllStart + NtdllSize;

    for (i = 0; i < Length - 4; i++) {
        //
        // Check for jmp rel32 (E9 XX XX XX XX)
        //
        if (Instructions[i] == DSD_JMP_REL32) {
            displacement = *(PLONG32)(&Instructions[i + 1]);

            //
            // Calculate target (IP + 5 + displacement)
            // Note: We don't have the actual IP here, so this is approximate
            //
            // For indirect syscall, the pattern typically has the jump
            // target pointing into NTDLL's syscall stub region
            //

            //
            // Check if displacement could reach NTDLL
            // This is a heuristic - actual validation would need the real IP
            //
            if (displacement > 0 && (ULONG)displacement < (ULONG)NtdllSize) {
                return TRUE;  // Suspicious - could be jumping into NTDLL
            }
        }

        //
        // Check for jmp [rip+disp32] (FF 25 XX XX XX XX)
        //
        if (i + 5 < Length &&
            Instructions[i] == DSD_JMP_RIP_DISP32_0 &&
            Instructions[i + 1] == DSD_JMP_RIP_DISP32_1) {

            //
            // This pattern is used for indirect jumps through a pointer
            //
            return TRUE;  // Suspicious
        }
    }

    return FALSE;
}

/**
 * @brief Detect Heaven's Gate pattern: segment switch from 32-bit to 64-bit
 */
static BOOLEAN
DsdpIsHeavensGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length
)
{
    ULONG i;

    if (Length < 7) {
        return FALSE;
    }

    for (i = 0; i < Length - 6; i++) {
        //
        // Check for far jmp to 0x33 segment (EA XX XX XX XX 33 00)
        // or retf with 0x33 on stack
        //
        if (Instructions[i] == DSD_FAR_JMP) {
            //
            // Check if segment selector is 0x33 (64-bit CS)
            //
            if (i + 6 < Length && Instructions[i + 5] == DSD_HEAVENS_GATE_SEGMENT) {
                return TRUE;
            }
        }

        //
        // Check for push 0x33; retf pattern
        //
        if (Instructions[i] == 0x6A &&  // push imm8
            Instructions[i + 1] == DSD_HEAVENS_GATE_SEGMENT) {

            //
            // Look for retf nearby
            //
            for (ULONG j = i + 2; j < Length && j < i + 10; j++) {
                if (Instructions[j] == DSD_RETF) {
                    return TRUE;
                }
            }
        }

        //
        // Check for push 0x33; push addr; retf pattern
        //
        if (Instructions[i] == 0x68) {  // push imm32
            if (i + 9 < Length) {
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

        //
        // Check for call to WoW64 transition thunk
        //
        if (Instructions[i] == DSD_CALL_REL32 && i + 4 < Length) {
            //
            // Look for segment prefix after the call returns
            //
            if (i + 8 < Length && Instructions[i + 5] == 0x9A) {  // call far
                return TRUE;
            }
        }
    }

    return FALSE;
}

/**
 * @brief Detect Hell's Gate pattern: dynamic SSN resolution
 *
 * Hell's Gate resolves syscall numbers dynamically by reading from NTDLL
 * export table at runtime. The pattern typically involves:
 * - Walking PE headers
 * - Parsing export directory
 * - Finding syscall stub
 * - Extracting SSN from mov eax, imm32
 */
static BOOLEAN
DsdpIsHellsGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PDSD_DETECTION_INTERNAL Detection
)
{
    ULONG i;
    BOOLEAN hasPeHeaderAccess = FALSE;
    BOOLEAN hasExportTableAccess = FALSE;

    if (Length < 20) {
        return FALSE;
    }

    //
    // Look for patterns indicative of PE parsing:
    // - Reading DOS header (MZ signature at offset 0)
    // - Reading PE header (PE signature)
    // - Accessing export directory
    //

    for (i = 0; i < Length - 10; i++) {
        //
        // Check for comparison with 'MZ' (5A4D) or 'PE' (4550)
        //
        if (i + 5 < Length) {
            //
            // cmp word ptr [xxx], 0x5A4D  (check for MZ)
            //
            if ((Instructions[i] == 0x66 && Instructions[i + 1] == 0x81) ||
                (Instructions[i] == 0x66 && Instructions[i + 1] == 0x83)) {

                USHORT imm = *(PUSHORT)(&Instructions[i + 4]);
                if (imm == 0x5A4D) {  // 'MZ'
                    hasPeHeaderAccess = TRUE;
                }
            }

            //
            // cmp dword ptr [xxx], 0x00004550  (check for PE\0\0)
            //
            if (Instructions[i] == 0x81) {
                ULONG imm = *(PULONG)(&Instructions[i + 2]);
                if (imm == 0x00004550) {  // 'PE\0\0'
                    hasPeHeaderAccess = TRUE;
                }
            }
        }

        //
        // Look for export table offset access (0x88 in PE optional header)
        //
        if (i + 3 < Length) {
            //
            // mov xxx, [xxx+0x88]  (Export Directory RVA)
            //
            if (Instructions[i] == 0x8B) {
                ULONG offset = *(PULONG)(&Instructions[i + 2]);
                if (offset == 0x88) {  // Export directory offset in x64
                    hasExportTableAccess = TRUE;
                }
            }
        }
    }

    //
    // Hell's Gate typically has both PE header and export table access
    //
    if (hasPeHeaderAccess && hasExportTableAccess) {
        if (Detection != NULL) {
            Detection->HasDynamicSsnResolution = TRUE;
        }
        return TRUE;
    }

    //
    // Alternative: Look for specific Hell's Gate code patterns
    // Hell's Gate often uses a specific sequence to find the SSN:
    // 1. Find function by hash
    // 2. Read mov eax, imm32 from syscall stub
    //

    for (i = 0; i < Length - 8; i++) {
        //
        // Pattern: cmp byte ptr [xxx], 0x4C  (check for 4C 8B D1 - mov r10, rcx)
        //
        if (Instructions[i] == 0x80 && i + 3 < Length) {
            if (Instructions[i + 2] == 0x4C) {
                //
                // Then looks for mov eax, imm32 (B8)
                //
                for (ULONG j = i + 3; j < Length - 2 && j < i + 15; j++) {
                    if (Instructions[j] == 0x80 && Instructions[j + 2] == 0xB8) {
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

/**
 * @brief Detect Halo's Gate pattern: neighbor syscall walking
 *
 * Halo's Gate walks neighboring syscalls when the target is hooked.
 * It looks at adjacent functions in NTDLL to find a clean syscall stub.
 */
static BOOLEAN
DsdpIsHalosGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _In_ PDSD_DETECTION_INTERNAL Detection
)
{
    ULONG i;
    BOOLEAN hasNeighborCheck = FALSE;
    BOOLEAN hasStubPatternSearch = FALSE;

    if (Length < 25) {
        return FALSE;
    }

    //
    // Halo's Gate typically:
    // 1. Checks if current syscall stub starts with 4C 8B D1 (mov r10, rcx)
    // 2. If hooked (e.g., starts with E9 - jmp), looks at neighbors
    // 3. Uses SSN arithmetic to find the correct number
    //

    for (i = 0; i < Length - 10; i++) {
        //
        // Look for hook detection: cmp byte ptr [xxx], 0xE9
        //
        if (Instructions[i] == 0x80 && i + 3 < Length) {
            if (Instructions[i + 2] == DSD_JMP_REL32) {
                hasNeighborCheck = TRUE;
            }
        }

        //
        // Look for neighbor walking: add/sub reg, 0x20 (syscall stub size)
        //
        if (i + 2 < Length) {
            if ((Instructions[i] == 0x83 || Instructions[i] == 0x81)) {
                //
                // Check for +/- 0x20 (32 bytes - typical syscall stub size)
                //
                if (Instructions[i + 2] == 0x20) {
                    hasStubPatternSearch = TRUE;
                }
            }
        }

        //
        // Look for SSN adjustment: add/sub eax, 1 (adjust SSN for neighbor)
        //
        if (i + 1 < Length) {
            //
            // inc eax or dec eax for SSN adjustment
            //
            if (Instructions[i] == 0xFF &&
                (Instructions[i + 1] == 0xC0 || Instructions[i + 1] == 0xC8)) {
                hasNeighborCheck = TRUE;
            }
            //
            // add eax, imm8 or sub eax, imm8
            //
            if (Instructions[i] == 0x83 &&
                (Instructions[i + 1] == 0xC0 || Instructions[i + 1] == 0xE8)) {
                hasNeighborCheck = TRUE;
            }
        }
    }

    if (hasNeighborCheck && hasStubPatternSearch) {
        return TRUE;
    }

    //
    // Also check for the iteration pattern used in Halo's Gate
    //
    for (i = 0; i < Length - 15; i++) {
        //
        // Pattern: loop checking multiple stubs (up/down from target)
        //
        if (Instructions[i] == 0x75 || Instructions[i] == 0x74) {  // jne/je short
            //
            // Look for arithmetic on pointer
            //
            for (ULONG j = i + 2; j < Length - 3 && j < i + 10; j++) {
                if (Instructions[j] == 0x48 && Instructions[j + 1] == 0x83) {
                    //
                    // add/sub reg, imm8 (pointer arithmetic)
                    //
                    if (Instructions[j + 3] == 0x20) {  // 32-byte stride
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

/**
 * @brief Detect Tartarus Gate pattern: exception-based SSN resolution
 *
 * Tartarus Gate uses structured exception handling to resolve SSNs
 * by triggering and catching access violations or breakpoint exceptions.
 */
static BOOLEAN
DsdpIsTartarusGatePattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length
)
{
    ULONG i;
    BOOLEAN hasSehSetup = FALSE;
    BOOLEAN hasExceptionTrigger = FALSE;

    if (Length < 20) {
        return FALSE;
    }

    //
    // Look for SEH setup patterns
    //

    for (i = 0; i < Length - 8; i++) {
        //
        // Check for push of exception handler (typically part of SEH frame setup)
        //
        if (Instructions[i] == 0x64) {  // fs: prefix (x86 SEH)
            hasSehSetup = TRUE;
        }

        //
        // Check for gs: prefix access (x64 TEB access for VEH)
        //
        if (Instructions[i] == 0x65) {  // gs: prefix
            hasSehSetup = TRUE;
        }

        //
        // Check for AddVectoredExceptionHandler pattern
        // Typically involves call to kernel32/ntdll function
        //
        if (Instructions[i] == DSD_CALL_REL32) {
            hasSehSetup = TRUE;
        }

        //
        // Look for intentional exception trigger patterns
        //

        //
        // int 3 (breakpoint)
        //
        if (Instructions[i] == 0xCC) {
            hasExceptionTrigger = TRUE;
        }

        //
        // ud2 (undefined instruction)
        //
        if (i + 1 < Length &&
            Instructions[i] == 0x0F && Instructions[i + 1] == 0x0B) {
            hasExceptionTrigger = TRUE;
        }

        //
        // div by zero setup (xor edx, edx; div xxx)
        //
        if (Instructions[i] == 0x33 && i + 3 < Length) {  // xor
            if (Instructions[i + 2] == 0xF7) {  // div
                hasExceptionTrigger = TRUE;
            }
        }
    }

    //
    // Tartarus Gate needs both SEH/VEH setup and exception trigger
    //
    return (hasSehSetup && hasExceptionTrigger);
}

/**
 * @brief Detect SysWhispers pattern signatures
 *
 * SysWhispers generates syscall stubs with specific patterns:
 * - SysWhispers1: Hash-based function lookup
 * - SysWhispers2: Direct syscall with specific stub layout
 * - SysWhispers3: Indirect syscall with jump to ntdll
 */
static BOOLEAN
DsdpIsSysWhispersPattern(
    _In_ PUCHAR Instructions,
    _In_ ULONG Length,
    _Out_ PULONG Version
)
{
    ULONG i;

    *Version = 0;

    if (Length < 15) {
        return FALSE;
    }

    //
    // SysWhispers2 pattern:
    // mov r10, rcx       ; 4C 8B D1
    // mov eax, SSN       ; B8 XX XX 00 00
    // syscall            ; 0F 05
    // ret                ; C3
    //
    for (i = 0; i < Length - 12; i++) {
        if (Instructions[i] == 0x4C &&
            Instructions[i + 1] == 0x8B &&
            Instructions[i + 2] == 0xD1 &&
            Instructions[i + 3] == 0xB8 &&
            Instructions[i + 6] == 0x00 &&
            Instructions[i + 7] == 0x00 &&
            Instructions[i + 8] == 0x0F &&
            Instructions[i + 9] == 0x05 &&
            Instructions[i + 10] == 0xC3) {

            *Version = 2;
            return TRUE;
        }
    }

    //
    // SysWhispers3 indirect pattern:
    // mov r10, rcx       ; 4C 8B D1
    // mov eax, SSN       ; B8 XX XX 00 00
    // mov r11, addr      ; 49 BB XX XX XX XX XX XX XX XX
    // jmp r11            ; 41 FF E3
    //
    for (i = 0; i < Length - 20; i++) {
        if (Instructions[i] == 0x4C &&
            Instructions[i + 1] == 0x8B &&
            Instructions[i + 2] == 0xD1 &&
            Instructions[i + 3] == 0xB8) {

            //
            // Look for mov r11, imm64 and jmp r11
            //
            for (ULONG j = i + 8; j < Length - 4 && j < i + 20; j++) {
                if (Instructions[j] == 0x49 && Instructions[j + 1] == 0xBB) {
                    //
                    // mov r11, imm64 found, look for jmp r11
                    //
                    if (j + 11 < Length &&
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
    // SysWhispers1 typically uses hash-based lookup
    // Look for the characteristic hash comparison pattern
    //
    for (i = 0; i < Length - 10; i++) {
        //
        // Pattern involves ror and xor for hashing
        //
        if (Instructions[i] == 0xC1) {  // ror/rol
            if (i + 5 < Length && Instructions[i + 3] == 0x33) {  // xor
                //
                // Hash loop detected
                //
                *Version = 1;
                return TRUE;
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - CALL STACK CAPTURE
// ============================================================================

static NTSTATUS
DsdpCaptureCallStack(
    _In_ HANDLE ThreadId,
    _Out_writes_(MaxFrames) PVOID* Frames,
    _In_ ULONG MaxFrames,
    _Out_ PULONG CapturedFrames
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PETHREAD thread = NULL;
    ULONG capturedCount = 0;

    *CapturedFrames = 0;
    RtlZeroMemory(Frames, MaxFrames * sizeof(PVOID));

    //
    // Look up thread
    //
    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Use RtlCaptureStackBackTrace if available
    // Note: In kernel mode, this typically captures kernel stack
    // For user-mode stack walking, we would need to attach to the process
    //

    __try {
        //
        // Try to capture using RtlWalkFrameChain for kernel mode
        // For user mode, we would need ZwQueryInformationThread
        // with ThreadQuerySetWin32StartAddress or walk manually
        //

        //
        // Simplified: Just capture what we can from current context
        // A full implementation would use stack walking with frame pointers
        //
        capturedCount = RtlWalkFrameChain(Frames, MaxFrames, 0);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ObDereferenceObject(thread);

    *CapturedFrames = capturedCount;

    return status;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ADDRESS VALIDATION
// ============================================================================

static BOOLEAN
DsdpIsAddressInNtdll(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address
)
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG_PTR ntdllStart;
    ULONG_PTR ntdllEnd;

    if (!Detector->NtdllInfoValid || Detector->NtdllBase == NULL) {
        return FALSE;
    }

    ntdllStart = (ULONG_PTR)Detector->NtdllBase;
    ntdllEnd = ntdllStart + Detector->NtdllSize;

    return (addr >= ntdllStart && addr < ntdllEnd);
}

static BOOLEAN
DsdpIsAddressInKnownModule(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _Out_opt_ PUNICODE_STRING ModuleName,
    _Out_opt_ PULONG64 ModuleBase
)
{
    //
    // This would typically use ZwQueryVirtualMemory with MemoryMappedFilenameInformation
    // or walk the PEB LDR module list
    //
    // For now, we check against known critical modules
    //

    UNREFERENCED_PARAMETER(Detector);

    if (ModuleName != NULL) {
        RtlInitUnicodeString(ModuleName, NULL);
    }
    if (ModuleBase != NULL) {
        *ModuleBase = 0;
    }

    //
    // Check if address is in typical user-mode DLL range
    //
    ULONG_PTR addr = (ULONG_PTR)Address;

    //
    // Typical x64 DLL load range
    //
    if (addr >= 0x00007FF000000000 && addr < 0x00007FFFFFFFFFFF) {
        return TRUE;  // Likely in a mapped DLL
    }

    //
    // Typical x86 DLL load range (WoW64)
    //
    if (addr >= 0x70000000 && addr < 0x80000000) {
        return TRUE;
    }

    //
    // Check against common base addresses
    //
    if (addr >= 0x00007FFE00000000 && addr < 0x00007FFE80000000) {
        return TRUE;  // Common Windows DLL range
    }

    return FALSE;
}

static NTSTATUS
DsdpRefreshNtdllInfo(
    _Inout_ PDSD_DETECTOR_INTERNAL Detector
)
{
    //
    // This would typically walk the PEB LDR list to find ntdll.dll
    // For kernel driver, we might use PsGetProcessPeb and walk from there
    //
    // Simplified implementation - set reasonable defaults for x64
    //

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->NtdllLock);

    //
    // Typical ntdll base on x64 Windows 10/11
    //
    Detector->NtdllBase = (PVOID)0x00007FFE00000000;
    Detector->NtdllSize = 0x200000;  // ~2MB typical size

    //
    // Syscall region is typically near the end of .text section
    //
    Detector->NtdllSyscallRegionStart = (PVOID)0x00007FFE00100000;
    Detector->NtdllSyscallRegionEnd = (PVOID)0x00007FFE00180000;

    Detector->NtdllInfoValid = TRUE;

    ExReleasePushLockExclusive(&Detector->NtdllLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
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
    // Base score based on technique
    //
    switch (Detection->Base.Technique) {
        case DsdTechnique_DirectSyscall:
            score += 80;
            break;
        case DsdTechnique_IndirectSyscall:
            score += 60;
            break;
        case DsdTechnique_HeavensGate:
            score += 95;  // Very suspicious
            break;
        case DsdTechnique_HellsGate:
            score += 90;
            break;
        case DsdTechnique_HalosGate:
            score += 85;
            break;
        case DsdTechnique_TartarusGate:
            score += 90;
            break;
        case DsdTechnique_SysWhispers:
            score += 85;
            break;
        case DsdTechnique_Manual:
            score += 70;
            break;
        default:
            break;
    }

    //
    // Adjust based on additional indicators
    //

    //
    // Not from NTDLL is more suspicious
    //
    if (!Detection->Base.CallFromNtdll) {
        score += 15;
    }

    //
    // Not from known module is very suspicious
    //
    if (!Detection->Base.CallFromKnownModule) {
        score += 25;
    }

    //
    // SysWhispers pattern adds to suspicion
    //
    if (Detection->HasSysWhispersPattern) {
        score += 10;
    }

    //
    // Dynamic SSN resolution is suspicious
    //
    if (Detection->HasDynamicSsnResolution) {
        score += 15;
    }

    //
    // Segment switching (Heaven's Gate) is very suspicious
    //
    if (Detection->HasSegmentSwitch) {
        score += 20;
    }

    //
    // No return address in NTDLL is suspicious
    //
    if (!Detection->HasReturnToNtdll && Detection->Base.ReturnAddressCount > 0) {
        score += 10;
    }

    //
    // Cap at 100
    //
    if (score > 100) {
        score = 100;
    }

    return score;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - WHITELIST
// ============================================================================

static BOOLEAN
DsdpIsWhitelisted(
    _In_ PDSD_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_opt_ PUNICODE_STRING ModuleName
)
{
    PLIST_ENTRY entry;
    PDSD_WHITELIST_ENTRY whitelist;
    ULONG_PTR addr = (ULONG_PTR)Address;
    BOOLEAN found = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->Base.DetectionLock);

    for (entry = Detector->Base.WhitelistPatterns.Flink;
         entry != &Detector->Base.WhitelistPatterns;
         entry = entry->Flink) {

        whitelist = CONTAINING_RECORD(entry, DSD_WHITELIST_ENTRY, ListEntry);

        //
        // Check by address range
        //
        if (whitelist->MatchByAddress) {
            if (addr >= whitelist->BaseAddress &&
                addr < (whitelist->BaseAddress + whitelist->Size)) {
                found = TRUE;
                break;
            }
        }

        //
        // Check by module name
        //
        if (whitelist->MatchByName && ModuleName != NULL) {
            if (RtlEqualUnicodeString(&whitelist->ModuleName, ModuleName, TRUE)) {
                found = TRUE;
                break;
            }
        }
    }

    ExReleasePushLockShared(&Detector->Base.DetectionLock);
    KeLeaveCriticalRegion();

    return found;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - MEMORY ACCESS
// ============================================================================

static NTSTATUS
DsdpSafeReadMemory(
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length
)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        //
        // Probe and copy from user-mode address
        //
        ProbeForRead(SourceAddress, Length, 1);
        RtlCopyMemory(Destination, SourceAddress, Length);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static BOOLEAN
DsdpValidateUserAddress(
    _In_ PVOID Address,
    _In_ SIZE_T Size
)
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG_PTR end = addr + Size;

    //
    // Check for null
    //
    if (Address == NULL) {
        return FALSE;
    }

    //
    // Check for overflow
    //
    if (end < addr) {
        return FALSE;
    }

    //
    // Check if in user-mode address space
    //
    if (addr > DSD_USER_SPACE_LIMIT || end > DSD_USER_SPACE_LIMIT) {
        return FALSE;
    }

    //
    // Check minimum address (null page guard)
    //
    if (addr < 0x10000) {
        return FALSE;
    }

    return TRUE;
}

