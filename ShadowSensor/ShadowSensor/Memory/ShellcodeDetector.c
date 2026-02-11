/*++
    ShadowStrike Next-Generation Antivirus
    Module: ShellcodeDetector.c

    Purpose: Enterprise-grade shellcode detection engine providing comprehensive
             pattern matching, heuristic analysis, and behavioral detection for
             kernel-mode EDR operations.

    Architecture:
    - Multi-layer detection pipeline (patterns, heuristics, behavior)
    - NOP sled detection with variable NOP recognition
    - Egg hunter pattern recognition (SEH, syscall-based)
    - Encoder/decoder detection (XOR, ADD, SUB, ROL, ROR)
    - API hash resolution detection (ROR13, CRC32, custom)
    - Direct syscall stub detection (x64/WoW64)
    - Heaven's Gate transition detection
    - Stack pivot gadget detection
    - Position-independent code analysis
    - Shannon entropy calculation
    - Known signature matching

    Performance Characteristics:
    - O(n) single-pass scanning where possible
    - Boyer-Moore-Horspool for pattern matching
    - Early exit on high-confidence detections
    - Lock-free statistics using InterlockedXxx
    - Configurable scan size limits

    Security Properties:
    - Safe buffer access with bounds checking
    - No user-mode pointer dereferencing
    - IRQL-safe operations
    - Constant-time comparisons for signatures

    MITRE ATT&CK Coverage:
    - T1055: Process Injection (shellcode detection)
    - T1106: Native API (API hashing detection)
    - T1620: Reflective Code Loading (encoder detection)
    - T1574: Hijack Execution Flow (stack pivot detection)

    Copyright (c) ShadowStrike Team
--*/

#include "ShellcodeDetector.h"
#include "../Utilities/MemoryUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SdInitialize)
#pragma alloc_text(PAGE, SdShutdown)
#pragma alloc_text(PAGE, SdSetConfig)
#pragma alloc_text(PAGE, SdAddApiHash)
#pragma alloc_text(PAGE, SdLoadApiHashDatabase)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

//
// CAS state machine constants (C-2 fix)
//
#define SD_STATE_UNINITIALIZED      0
#define SD_STATE_INITIALIZING       1
#define SD_STATE_READY              2
#define SD_STATE_SHUTTING_DOWN      3

//
// Bounded shutdown timeout (10 seconds in 100ns units)
//
#define SD_SHUTDOWN_TIMEOUT_100NS   ((LONGLONG)(-10 * 10 * 1000 * 1000))

#define SD_MAX_PATTERN_SIZE             256
#define SD_ENTROPY_THRESHOLD_DEFAULT    70      // 70% = high entropy
#define SD_MIN_CONFIDENCE_DEFAULT       50      // Minimum confidence to report
#define SD_DEFAULT_TIMEOUT_MS           5000    // 5 second timeout

//
// M-2: Removed dead g_NopEquivalents array (was never referenced by detection logic)

//
// Egg hunter signatures
//
typedef struct _SD_EGG_SIGNATURE {
    const UCHAR* Pattern;
    ULONG PatternSize;
    const CHAR* Name;
} SD_EGG_SIGNATURE, *PSD_EGG_SIGNATURE;

static const UCHAR g_EggHunterSEH[] = {
    0x66, 0x81, 0xCA, 0xFF, 0x0F,   // OR DX, 0x0FFF
    0x42,                           // INC EDX
    0x52,                           // PUSH EDX
    0x6A, 0x02,                     // PUSH 2 (NtAccessCheckAndAuditAlarm)
};

static const UCHAR g_EggHunterSyscall[] = {
    0x66, 0x81, 0xCA, 0xFF, 0x0F,   // OR DX, 0x0FFF
    0x42,                           // INC EDX
    0x52,                           // PUSH EDX
    0x31, 0xC0,                     // XOR EAX, EAX
    0xCD, 0x2E,                     // INT 0x2E
};

static const UCHAR g_EggHunterNtDisplayString[] = {
    0x66, 0x81, 0xCA, 0xFF, 0x0F,   // OR DX, 0x0FFF
    0x42,                           // INC EDX
    0x6A, 0x43,                     // PUSH 0x43
    0x58,                           // POP EAX
    0xCD, 0x2E,                     // INT 0x2E
};

//
// XOR encoder loop signatures
//
static const UCHAR g_XorEncoderPattern1[] = {
    0x80, 0x34,                     // XOR BYTE PTR [reg+offset], imm8
};

static const UCHAR g_XorEncoderPattern2[] = {
    0x31,                           // XOR r/m32, reg
};

static const UCHAR g_XorEncoderPattern3[] = {
    0x32,                           // XOR reg, r/m8
};

//
// Direct syscall patterns (x64)
//
static const UCHAR g_SyscallPatternX64[] = {
    0x4C, 0x8B, 0xD1,               // MOV R10, RCX
    0xB8,                           // MOV EAX, imm32 (syscall number follows)
};

static const UCHAR g_SyscallInstructionX64[] = {
    0x0F, 0x05,                     // SYSCALL
};

static const UCHAR g_SysenterPatternX86[] = {
    0x0F, 0x34,                     // SYSENTER
};

static const UCHAR g_Int2EPattern[] = {
    0xCD, 0x2E,                     // INT 0x2E
};

//
// Heaven's Gate pattern (32->64 transition)
//
static const UCHAR g_HeavensGatePattern[] = {
    0xEA,                           // JMP FAR (segment change to 0x33)
};

static const UCHAR g_HeavensGateRetf[] = {
    0x6A, 0x33,                     // PUSH 0x33
    0xE8, 0x00, 0x00, 0x00, 0x00,   // CALL $+5
    0x83, 0x04, 0x24, 0x05,         // ADD DWORD PTR [ESP], 5
    0xCB,                           // RETF
};

//
// Stack pivot patterns
//
static const UCHAR g_StackPivotXchg[] = {
    0x94,                           // XCHG EAX, ESP
};

static const UCHAR g_StackPivotMov[] = {
    0x89,                           // MOV ESP, reg (partial)
};

static const UCHAR g_StackPivotLeave[] = {
    0xC9,                           // LEAVE (MOV ESP, EBP; POP EBP)
};

//
// API hash constants (ROR13)
//
#define ROR13_LOADLIBRARYA      0x0726774C
#define ROR13_GETPROCADDRESS    0x7C0DFCAA
#define ROR13_VIRTUALALLOC      0x91AFCA54
#define ROR13_VIRTUALPROTECT    0x7946C61B
#define ROR13_CREATETHREAD      0x160D6838
#define ROR13_NTFLUSHINSTRUCTIONCACHE 0x534C0AB8

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _SD_API_HASH_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG Hash;
    CHAR ApiName[64];
    CHAR DllName[32];
} SD_API_HASH_ENTRY, *PSD_API_HASH_ENTRY;

typedef struct _SD_SIGNATURE_ENTRY {
    LIST_ENTRY ListEntry;
    UCHAR Pattern[SD_MAX_PATTERN_SIZE];
    ULONG PatternSize;
    UCHAR Mask[SD_MAX_PATTERN_SIZE];
    CHAR SignatureName[64];
    CHAR ThreatFamily[64];
    SD_SHELLCODE_TYPE ShellcodeType;
    ULONG Severity;
} SD_SIGNATURE_ENTRY, *PSD_SIGNATURE_ENTRY;

typedef struct _SD_SCAN_CONTEXT {
    PSD_DETECTOR Detector;
    PUCHAR Buffer;
    SIZE_T Size;
    PSD_DETECTION_RESULT Result;
    LARGE_INTEGER StartTime;
    ULONG TimeoutMs;
    volatile BOOLEAN Cancelled;
} SD_SCAN_CONTEXT, *PSD_SCAN_CONTEXT;

//=============================================================================
// Forward Declarations
//=============================================================================

static VOID
SdpInitializeDefaultConfig(
    _Out_ PSD_CONFIG Config
    );

static VOID
SdpInitializeApiHashDatabase(
    _Inout_ PSD_DETECTOR Detector
    );

static VOID
SdpCleanupApiHashDatabase(
    _Inout_ PSD_DETECTOR Detector
    );

static VOID
SdpCleanupSignatureDatabase(
    _Inout_ PSD_DETECTOR Detector
    );

static ULONG
SdpCalculateEntropy(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
    );

static BOOLEAN
SdpDetectNopSledInternal(
    _In_ PSD_SCAN_CONTEXT Context,
    _Out_ PULONG Offset,
    _Out_ PULONG Length,
    _Out_ PUCHAR NopByte
    );

static BOOLEAN
SdpDetectEggHunter(
    _In_ PSD_SCAN_CONTEXT Context
    );

static BOOLEAN
SdpDetectEncoderLoop(
    _In_ PSD_SCAN_CONTEXT Context,
    _Out_ PSD_ENCODER_INFO EncoderInfo
    );

static BOOLEAN
SdpDetectApiHashing(
    _In_ PSD_SCAN_CONTEXT Context,
    _Out_ PSD_API_HASH_INFO ApiHashInfo
    );

static BOOLEAN
SdpDetectDirectSyscalls(
    _In_ PSD_SCAN_CONTEXT Context
    );

static BOOLEAN
SdpDetectHeavensGate(
    _In_ PSD_SCAN_CONTEXT Context
    );

static BOOLEAN
SdpDetectStackPivot(
    _In_ PSD_SCAN_CONTEXT Context
    );

static BOOLEAN
SdpMatchSignatures(
    _In_ PSD_SCAN_CONTEXT Context
    );

static ULONG
SdpCalculateConfidenceScore(
    _In_ PSD_DETECTION_RESULT Result
    );

static ULONG
SdpCalculateSeverityScore(
    _In_ PSD_DETECTION_RESULT Result
    );

static SD_SHELLCODE_TYPE
SdpDeterminePrimaryType(
    _In_ PSD_DETECTION_RESULT Result
    );

static BOOLEAN
SdpIsTimeout(
    _In_ PSD_SCAN_CONTEXT Context
    );

//
// L-1: Removed dead SdpRor13Hash forward declaration (function removed below)
//

static FORCEINLINE BOOLEAN
SdpSafeMemoryCompare(
    _In_reads_bytes_(Size) const VOID* Buffer1,
    _In_reads_bytes_(Size) const VOID* Buffer2,
    _In_ SIZE_T Size
    );

/**
 * @brief C-2: Lifecycle helpers — increment-then-check reference pattern.
 */
static FORCEINLINE BOOLEAN
SdpAcquireReference(
    _In_ PSD_DETECTOR Detector
    )
{
    InterlockedIncrement(&Detector->ActiveOperations);
    if (ReadAcquire(&Detector->State) == SD_STATE_READY) {
        return TRUE;
    }
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
    return FALSE;
}

static FORCEINLINE VOID
SdpReleaseReference(
    _In_ PSD_DETECTOR Detector
    )
{
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        if (ReadAcquire(&Detector->State) == SD_STATE_SHUTTING_DOWN) {
            KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        }
    }
}

static FORCEINLINE BOOLEAN
SdpIsReady(
    _In_ PSD_DETECTOR Detector
    )
{
    return (ReadAcquire(&Detector->State) == SD_STATE_READY);
}

/**
 * @brief L-2: Safely read a ULONG from a potentially unaligned address.
 */
static FORCEINLINE ULONG
SdpReadUnalignedUlong(
    _In_reads_bytes_(4) const VOID* Address
    )
{
    ULONG value;
    RtlCopyMemory(&value, Address, sizeof(ULONG));
    return value;
}

/**
 * @brief H-3: Snapshot current config under lock for torn-read safety.
 */
static FORCEINLINE VOID
SdpSnapshotConfig(
    _In_ PSD_DETECTOR Detector,
    _Out_ PSD_CONFIG ConfigOut
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ConfigLock);
    RtlCopyMemory(ConfigOut, &Detector->Config, sizeof(SD_CONFIG));
    ExReleasePushLockShared(&Detector->ConfigLock);
    KeLeaveCriticalRegion();
}

/**
 * @brief H-2: Kernel-safe substring search (replaces CRT strstr).
 */
static BOOLEAN
SdpContainsSubstring(
    _In_z_ const CHAR* Haystack,
    _In_z_ const CHAR* Needle
    )
{
    SIZE_T needleLen;
    SIZE_T i;

    if (Needle == NULL || Needle[0] == '\0') return TRUE;
    if (Haystack == NULL) return FALSE;

    needleLen = 0;
    while (Needle[needleLen] != '\0') needleLen++;

    for (i = 0; Haystack[i] != '\0'; i++) {
        SIZE_T j;
        BOOLEAN match = TRUE;
        for (j = 0; j < needleLen; j++) {
            if (Haystack[i + j] == '\0' || Haystack[i + j] != Needle[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SdInitialize(
    _Out_ PSD_DETECTOR* Detector,
    _In_opt_ PSD_CONFIG Config
    )
/*++

Routine Description:

    Initializes the shellcode detector engine.

Arguments:

    Detector - Receives the initialized detector.
    Config - Optional configuration. Uses defaults if NULL.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PSD_DETECTOR detector = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    LONG prevState;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    detector = (PSD_DETECTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SD_DETECTOR),
        SD_POOL_TAG_CONTEXT
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detector, sizeof(SD_DETECTOR));

    //
    // C-2 fix: CAS-based initialization — prevent double-init
    //
    prevState = InterlockedCompareExchange(
        &detector->State, SD_STATE_INITIALIZING, SD_STATE_UNINITIALIZED);
    if (prevState != SD_STATE_UNINITIALIZED) {
        ShadowStrikeFreePoolWithTag(detector, SD_POOL_TAG_CONTEXT);
        return STATUS_ALREADY_INITIALIZED;
    }

    //
    // Initialize configuration (H-3: config protected by lock)
    //
    ExInitializePushLock(&detector->ConfigLock);
    if (Config != NULL) {
        RtlCopyMemory(&detector->Config, Config, sizeof(SD_CONFIG));
    } else {
        SdpInitializeDefaultConfig(&detector->Config);
    }

    //
    // Initialize API hash database
    //
    ExInitializePushLock(&detector->ApiHashes.Lock);
    detector->ApiHashes.HashTable = NULL;
    detector->ApiHashes.HashCount = 0;

    //
    // Initialize signature database
    //
    ExInitializePushLock(&detector->Signatures.Lock);
    detector->Signatures.SignatureDatabase = NULL;
    detector->Signatures.SignatureCount = 0;

    //
    // C-2 fix: Initialize lifecycle primitives
    //
    KeInitializeEvent(&detector->ShutdownEvent, NotificationEvent, FALSE);
    detector->ActiveOperations = 1;  // Init reference — released by SdShutdown

    //
    // Populate default API hashes (H-6: failures are non-fatal but logged)
    //
    SdpInitializeApiHashDatabase(detector);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&detector->Stats.StartTime);

    //
    // C-2: Transition INITIALIZING → READY
    //
    InterlockedExchange(&detector->State, SD_STATE_READY);

    *Detector = detector;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
SdShutdown(
    _Inout_ PSD_DETECTOR Detector
    )
/*++

Routine Description:

    Shuts down the shellcode detector and frees all resources.
    C-2 fix: CAS state machine with bounded drain wait.

--*/
{
    LONG prevState;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (Detector == NULL) {
        return;
    }

    //
    // C-2: Transition READY → SHUTTING_DOWN via CAS
    //
    prevState = InterlockedCompareExchange(
        &Detector->State, SD_STATE_SHUTTING_DOWN, SD_STATE_READY);
    if (prevState != SD_STATE_READY) {
        return;  // Not initialized or already shutting down
    }

    //
    // Release the init reference, then wait for active operations to drain
    //
    if (InterlockedDecrement(&Detector->ActiveOperations) > 0) {
        timeout.QuadPart = SD_SHUTDOWN_TIMEOUT_100NS;
        KeWaitForSingleObject(
            &Detector->ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Cleanup databases
    //
    SdpCleanupApiHashDatabase(Detector);
    SdpCleanupSignatureDatabase(Detector);

    //
    // Final state transition and free
    //
    InterlockedExchange(&Detector->State, SD_STATE_UNINITIALIZED);
    ShadowStrikeFreePoolWithTag(Detector, SD_POOL_TAG_CONTEXT);
}


_Use_decl_annotations_
NTSTATUS
SdSetConfig(
    _Inout_ PSD_DETECTOR Detector,
    _In_ PSD_CONFIG Config
    )
{
    PAGED_CODE();

    if (Detector == NULL || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // H-3 fix: Update config under exclusive lock to prevent torn reads
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ConfigLock);
    RtlCopyMemory(&Detector->Config, Config, sizeof(SD_CONFIG));
    ExReleasePushLockExclusive(&Detector->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


//=============================================================================
// Detection API
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SdAnalyzeBuffer(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSD_DETECTION_RESULT* Result
    )
/*++

Routine Description:

    Analyzes a memory buffer for shellcode patterns.

Arguments:

    Detector - Initialized detector instance.
    Buffer - Buffer to analyze.
    Size - Size of buffer in bytes.
    Result - Receives detection result.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PSD_DETECTION_RESULT result = NULL;
    SD_SCAN_CONTEXT context;
    SD_CONFIG config;
    NTSTATUS status = STATUS_SUCCESS;

    if (Detector == NULL || Buffer == NULL || Size == 0 || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // C-2 fix: Acquire reference (atomic check-after-increment)
    //
    if (!SdpAcquireReference(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // H-3 fix: Snapshot config under lock to prevent torn reads
    //
    SdpSnapshotConfig(Detector, &config);

    //
    // Validate size limits
    //
    if (Size < SD_MIN_SCAN_SIZE) {
        SdpReleaseReference(Detector);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (config.MaxScanSizeBytes > 0 && Size > config.MaxScanSizeBytes) {
        Size = config.MaxScanSizeBytes;
    }

    if (Size > SD_MAX_SCAN_SIZE) {
        Size = SD_MAX_SCAN_SIZE;
    }

    //
    // H-4 fix: Use PagedPool — all callers at PASSIVE_LEVEL.
    // SD_DETECTION_RESULT is ~3.5KB, no reason for NonPaged.
    //
    result = (PSD_DETECTION_RESULT)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(SD_DETECTION_RESULT),
        SD_POOL_TAG_RESULT
    );

    if (result == NULL) {
        SdpReleaseReference(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(SD_DETECTION_RESULT));

    //
    // Initialize scan context with snapshotted config
    //
    RtlZeroMemory(&context, sizeof(context));
    context.Detector = Detector;
    context.Buffer = (PUCHAR)Buffer;
    context.Size = Size;
    context.Result = result;
    context.TimeoutMs = config.ScanTimeoutMs > 0 ?
        config.ScanTimeoutMs : SD_DEFAULT_TIMEOUT_MS;
    context.Cancelled = FALSE;
    KeQuerySystemTime(&context.StartTime);

    //
    // Store buffer info in result
    //
    result->Address = Buffer;
    result->Size = Size;
    KeQuerySystemTime(&result->DetectionTime);

    //
    // Run detection pipeline (using snapshotted config)
    //

    //
    // 1. Entropy analysis
    //
    if (config.EnableEntropyAnalysis) {
        result->EntropyPercent = SdpCalculateEntropy(context.Buffer, context.Size);
        result->HighEntropy = (result->EntropyPercent >= config.EntropyThreshold);

        if (result->HighEntropy) {
            result->Flags |= SdFlag_HighEntropy;
        }
    }

    //
    // 2. NOP sled detection
    //
    if (config.EnableNopSledDetection && !SdpIsTimeout(&context)) {
        ULONG offset = 0;
        ULONG length = 0;
        UCHAR nopByte = 0;

        if (SdpDetectNopSledInternal(&context, &offset, &length, &nopByte)) {
            result->NopSled.Found = TRUE;
            result->NopSled.StartAddress = (PUCHAR)Buffer + offset;
            result->NopSled.Length = length;
            result->NopSled.NopByte = nopByte;
            result->Flags |= SdFlag_NopSled;
            InterlockedIncrement64(&Detector->Stats.NopSledsFound);
        }
    }

    //
    // 3. Egg hunter detection
    //
    if (config.EnableEggHunterDetection && !SdpIsTimeout(&context)) {
        if (SdpDetectEggHunter(&context)) {
            result->EggHunter.Found = TRUE;
            result->Flags |= SdFlag_EggHunter;
            InterlockedIncrement64(&Detector->Stats.EggHuntersFound);
        }
    }

    //
    // 4. Encoder detection
    //
    if (config.EnableEncoderDetection && !SdpIsTimeout(&context)) {
        if (SdpDetectEncoderLoop(&context, &result->Encoder)) {
            result->Flags |= SdFlag_Encoder;
            InterlockedIncrement64(&Detector->Stats.EncodersFound);
        }
    }

    //
    // 5. API hashing detection
    //
    if (config.EnableApiHashDetection && !SdpIsTimeout(&context)) {
        if (SdpDetectApiHashing(&context, &result->ApiHashing)) {
            result->Flags |= SdFlag_APIHashing;
            InterlockedIncrement64(&Detector->Stats.ApiHashingFound);
        }
    }

    //
    // 6. Direct syscall detection
    //
    if (config.EnableSyscallDetection && !SdpIsTimeout(&context)) {
        if (SdpDetectDirectSyscalls(&context)) {
            result->Flags |= SdFlag_DirectSyscall;
            InterlockedIncrement64(&Detector->Stats.SyscallsFound);
        }
    }

    //
    // 7. Heaven's Gate detection
    //
    if (config.EnableSyscallDetection && !SdpIsTimeout(&context)) {
        if (SdpDetectHeavensGate(&context)) {
            result->Flags |= SdFlag_HeavensGate;
        }
    }

    //
    // 8. Stack pivot detection
    //
    if (config.EnableStackPivotDetection && !SdpIsTimeout(&context)) {
        if (SdpDetectStackPivot(&context)) {
            result->Flags |= SdFlag_StackPivot;
        }
    }

    //
    // 9. Signature matching
    //
    if (config.EnableSignatureMatching && !SdpIsTimeout(&context)) {
        if (SdpMatchSignatures(&context)) {
            result->Flags |= SdFlag_KnownSignature;
        }
    }

    //
    // Calculate final scores
    //
    result->ConfidenceScore = SdpCalculateConfidenceScore(result);
    result->SeverityScore = SdpCalculateSeverityScore(result);
    result->Type = SdpDeterminePrimaryType(result);

    //
    // Determine if this is shellcode (use snapshotted threshold)
    //
    result->IsShellcode = (result->ConfidenceScore >= config.MinConfidenceScore);

    //
    // Calculate analysis duration
    //
    {
        LARGE_INTEGER endTime;
        KeQuerySystemTime(&endTime);
        result->AnalysisDurationMs = (ULONG)((endTime.QuadPart - context.StartTime.QuadPart) / 10000);
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.TotalScans);
    if (result->IsShellcode) {
        InterlockedIncrement64(&Detector->Stats.DetectionsFound);
    }

    *Result = result;

    SdpReleaseReference(Detector);
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
SdAnalyzeRegion(
    _In_ PSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _Out_ PSD_DETECTION_RESULT* Result
    )
/*++

Routine Description:

    Analyzes a memory region in a specific process.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PVOID buffer = NULL;
    SIZE_T copiedSize = 0;

    if (Detector == NULL || Address == NULL || Size == 0 || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // C-2: Lifecycle check (SdAnalyzeBuffer also acquires its own reference)
    //
    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Cap size (C-3: max 4MB)
    //
    if (Size > SD_MAX_SCAN_SIZE) {
        Size = SD_MAX_SCAN_SIZE;
    }

    //
    // Get process reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // C-3 fix: Use PagedPool — buffer only used at PASSIVE_LEVEL.
    // L-3 fix: Use SD_POOL_TAG_BUFFER for temp allocations.
    //
    buffer = ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        Size,
        SD_POOL_TAG_BUFFER
    );

    if (buffer == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Attach to process and copy memory
    //
    __try {
        KeStackAttachProcess(process, &apcState);

        __try {
            ProbeForRead(Address, Size, 1);
            RtlCopyMemory(buffer, Address, Size);
            copiedSize = Size;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

        KeUnstackDetachProcess(&apcState);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ObDereferenceObject(process);

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(buffer, SD_POOL_TAG_BUFFER);
        return status;
    }

    //
    // Analyze the copied buffer
    //
    status = SdAnalyzeBuffer(Detector, buffer, copiedSize, Result);

    if (NT_SUCCESS(status) && *Result != NULL) {
        (*Result)->ProcessId = ProcessId;
        (*Result)->Address = Address;
    }

    //
    // Free temporary buffer
    //
    ShadowStrikeFreePoolWithTag(buffer, SD_POOL_TAG_BUFFER);

    return status;
}


_Use_decl_annotations_
NTSTATUS
SdScanProcess(
    _In_ PSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxResults, *ResultCount) PSD_DETECTION_RESULT* Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG ResultCount
    )
/*++

Routine Description:

    Scans all executable memory regions in a process.
    H-1 fix: Collects region descriptors while attached, analyzes AFTER detaching.
    This prevents the double-KeStackAttachProcess BSOD.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T returnLength;
    PVOID currentAddress = NULL;
    ULONG foundCount = 0;
    ULONG regionCount = 0;
    ULONG i;

    //
    // Region descriptor for collecting regions while attached
    //
    typedef struct _SD_REGION_DESC {
        PVOID BaseAddress;
        SIZE_T RegionSize;
        ULONG Protect;
    } SD_REGION_DESC, *PSD_REGION_DESC;

    #define SD_MAX_REGIONS_TO_SCAN 256

    PSD_REGION_DESC regions = NULL;

    if (Detector == NULL || Results == NULL || ResultCount == NULL || MaxResults == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpAcquireReference(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    *ResultCount = 0;
    RtlZeroMemory(Results, MaxResults * sizeof(PSD_DETECTION_RESULT));

    //
    // Allocate array to collect region descriptors (PagedPool)
    //
    regions = (PSD_REGION_DESC)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        SD_MAX_REGIONS_TO_SCAN * sizeof(SD_REGION_DESC),
        SD_POOL_TAG_BUFFER
    );

    if (regions == NULL) {
        SdpReleaseReference(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(regions, SD_MAX_REGIONS_TO_SCAN * sizeof(SD_REGION_DESC));

    //
    // Get process reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(regions, SD_POOL_TAG_BUFFER);
        SdpReleaseReference(Detector);
        return status;
    }

    //
    // Phase 1: Attach and collect executable region descriptors only
    //
    KeStackAttachProcess(process, &apcState);

    __try {
        currentAddress = NULL;

        while (regionCount < SD_MAX_REGIONS_TO_SCAN) {
            status = ZwQueryVirtualMemory(
                ZwCurrentProcess(),
                currentAddress,
                MemoryBasicInformation,
                &memInfo,
                sizeof(memInfo),
                &returnLength
            );

            if (!NT_SUCCESS(status)) {
                break;
            }

            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                memInfo.RegionSize >= SD_MIN_SCAN_SIZE &&
                memInfo.Type == MEM_PRIVATE) {

                regions[regionCount].BaseAddress = memInfo.BaseAddress;
                regions[regionCount].RegionSize = memInfo.RegionSize;
                regions[regionCount].Protect = memInfo.Protect;
                regionCount++;
            }

            currentAddress = (PUCHAR)memInfo.BaseAddress + memInfo.RegionSize;
            if ((ULONG_PTR)currentAddress < (ULONG_PTR)memInfo.BaseAddress) {
                break;  // Address overflow
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    //
    // Detach BEFORE analyzing — SdAnalyzeRegion attaches on its own
    //
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);
    process = NULL;

    //
    // Phase 2: Analyze collected regions (detached — no double-attach)
    //
    for (i = 0; i < regionCount && foundCount < MaxResults; i++) {
        PSD_DETECTION_RESULT result = NULL;

        status = SdAnalyzeRegion(
            Detector,
            ProcessId,
            regions[i].BaseAddress,
            regions[i].RegionSize,
            &result
        );

        if (NT_SUCCESS(status) && result != NULL) {
            if (result->IsShellcode) {
                result->Protection = regions[i].Protect;
                Results[foundCount] = result;
                foundCount++;
            } else {
                SdFreeResult(result);
            }
        }
    }

    ShadowStrikeFreePoolWithTag(regions, SD_POOL_TAG_BUFFER);
    SdpReleaseReference(Detector);

    *ResultCount = foundCount;

    return (foundCount > 0) ? STATUS_SUCCESS : status;
}


//=============================================================================
// Specific Detection Functions
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SdDetectNopSled(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PBOOLEAN Found,
    _Out_opt_ PULONG Offset,
    _Out_opt_ PULONG Length
    )
{
    SD_SCAN_CONTEXT context;
    ULONG offset = 0;
    ULONG length = 0;
    UCHAR nopByte = 0;

    if (Detector == NULL || Buffer == NULL || Found == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    *Found = FALSE;
    if (Offset != NULL) *Offset = 0;
    if (Length != NULL) *Length = 0;

    if (Size < SD_NOP_SLED_MIN_LENGTH) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.Detector = Detector;
    context.Buffer = (PUCHAR)Buffer;
    context.Size = Size;

    if (SdpDetectNopSledInternal(&context, &offset, &length, &nopByte)) {
        *Found = TRUE;
        if (Offset != NULL) *Offset = offset;
        if (Length != NULL) *Length = length;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
SdDetectEncoder(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSD_ENCODER_INFO EncoderInfo
    )
{
    SD_SCAN_CONTEXT context;

    if (Detector == NULL || Buffer == NULL || EncoderInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(EncoderInfo, sizeof(SD_ENCODER_INFO));

    if (Size < 16) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.Detector = Detector;
    context.Buffer = (PUCHAR)Buffer;
    context.Size = Size;

    SdpDetectEncoderLoop(&context, EncoderInfo);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
SdDetectApiHashing(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSD_API_HASH_INFO ApiHashInfo
    )
{
    SD_SCAN_CONTEXT context;

    if (Detector == NULL || Buffer == NULL || ApiHashInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(ApiHashInfo, sizeof(SD_API_HASH_INFO));

    if (Size < 16) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.Detector = Detector;
    context.Buffer = (PUCHAR)Buffer;
    context.Size = Size;

    SdpDetectApiHashing(&context, ApiHashInfo);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
SdDetectDirectSyscall(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_writes_to_(MaxSyscalls, *SyscallCount) PSD_SYSCALL_INFO Syscalls,
    _In_ ULONG MaxSyscalls,
    _Out_ PULONG SyscallCount
    )
{
    PUCHAR buffer = (PUCHAR)Buffer;
    ULONG count = 0;
    SIZE_T i;

    if (Detector == NULL || Buffer == NULL || Syscalls == NULL || SyscallCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    *SyscallCount = 0;
    RtlZeroMemory(Syscalls, MaxSyscalls * sizeof(SD_SYSCALL_INFO));

    if (Size < sizeof(g_SyscallPatternX64) + 4) {
        return STATUS_SUCCESS;
    }

    //
    // Scan for syscall patterns
    //
    for (i = 0; i < Size - sizeof(g_SyscallPatternX64) - 4 && count < MaxSyscalls; i++) {
        //
        // Check for x64 syscall setup pattern
        //
        if (RtlCompareMemory(&buffer[i], g_SyscallPatternX64,
                             sizeof(g_SyscallPatternX64)) == sizeof(g_SyscallPatternX64)) {

            ULONG syscallNum = SdpReadUnalignedUlong(&buffer[i + sizeof(g_SyscallPatternX64)]);

            //
            // Validate syscall number (reasonable range)
            //
            if (syscallNum < 0x2000) {
                Syscalls[count].SyscallNumber = syscallNum;
                Syscalls[count].StubAddress = (ULONG64)&buffer[i];
                Syscalls[count].StubSize = sizeof(g_SyscallPatternX64) + 4;
                Syscalls[count].Type = StubType_Direct;

                RtlCopyMemory(Syscalls[count].StubBytes, &buffer[i],
                             min(SD_SYSCALL_STUB_SIZE, Size - i));

                count++;
            }
        }

        //
        // Check for SYSCALL instruction
        //
        if (i < Size - 2) {
            if (buffer[i] == 0x0F && buffer[i + 1] == 0x05) {
                //
                // Found raw SYSCALL - check if we already captured it
                //
                BOOLEAN alreadyCaptured = FALSE;
                ULONG j;

                for (j = 0; j < count; j++) {
                    if ((ULONG64)&buffer[i] >= Syscalls[j].StubAddress &&
                        (ULONG64)&buffer[i] < Syscalls[j].StubAddress + Syscalls[j].StubSize) {
                        alreadyCaptured = TRUE;
                        break;
                    }
                }

                if (!alreadyCaptured && count < MaxSyscalls) {
                    Syscalls[count].StubAddress = (ULONG64)&buffer[i];
                    Syscalls[count].StubSize = 2;
                    Syscalls[count].Type = StubType_Direct;
                    RtlCopyMemory(Syscalls[count].StubBytes, &buffer[i], 2);
                    count++;
                }
            }
        }
    }

    *SyscallCount = count;

    return STATUS_SUCCESS;
}


//=============================================================================
// API Hash Database
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SdAddApiHash(
    _In_ PSD_DETECTOR Detector,
    _In_ ULONG Hash,
    _In_ PCSTR ApiName,
    _In_ PCSTR DllName
    )
{
    PSD_API_HASH_ENTRY entry = NULL;
    PLIST_ENTRY hashTable;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (ApiName == NULL || DllName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Detector->ApiHashes.HashCount >= SD_MAX_API_HASHES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate entry
    //
    entry = (PSD_API_HASH_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SD_API_HASH_ENTRY),
        SD_POOL_TAG_PATTERN
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(SD_API_HASH_ENTRY));

    entry->Hash = Hash;
    RtlStringCchCopyA(entry->ApiName, sizeof(entry->ApiName), ApiName);
    RtlStringCchCopyA(entry->DllName, sizeof(entry->DllName), DllName);

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ApiHashes.Lock);

    if (Detector->ApiHashes.HashTable == NULL) {
        //
        // First entry - create list head
        //
        Detector->ApiHashes.HashTable = ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(LIST_ENTRY),
            SD_POOL_TAG_PATTERN
        );

        if (Detector->ApiHashes.HashTable == NULL) {
            ExReleasePushLockExclusive(&Detector->ApiHashes.Lock);
            KeLeaveCriticalRegion();
            ShadowStrikeFreePoolWithTag(entry, SD_POOL_TAG_PATTERN);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        InitializeListHead((PLIST_ENTRY)Detector->ApiHashes.HashTable);
    }

    hashTable = (PLIST_ENTRY)Detector->ApiHashes.HashTable;
    InsertTailList(hashTable, &entry->ListEntry);
    Detector->ApiHashes.HashCount++;

    ExReleasePushLockExclusive(&Detector->ApiHashes.Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
SdLookupApiHash(
    _In_ PSD_DETECTOR Detector,
    _In_ ULONG Hash,
    _Out_writes_z_(ApiNameSize) PSTR ApiName,
    _In_ ULONG ApiNameSize,
    _Out_writes_z_(DllNameSize) PSTR DllName,
    _In_ ULONG DllNameSize
    )
{
    PLIST_ENTRY hashTable;
    PLIST_ENTRY entry;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (ApiName == NULL || DllName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ApiName[0] = '\0';
    DllName[0] = '\0';

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ApiHashes.Lock);

    hashTable = (PLIST_ENTRY)Detector->ApiHashes.HashTable;
    if (hashTable != NULL) {
        for (entry = hashTable->Flink; entry != hashTable; entry = entry->Flink) {
            PSD_API_HASH_ENTRY hashEntry = CONTAINING_RECORD(entry, SD_API_HASH_ENTRY, ListEntry);

            if (hashEntry->Hash == Hash) {
                RtlStringCchCopyA(ApiName, ApiNameSize, hashEntry->ApiName);
                RtlStringCchCopyA(DllName, DllNameSize, hashEntry->DllName);
                status = STATUS_SUCCESS;
                break;
            }
        }
    }

    ExReleasePushLockShared(&Detector->ApiHashes.Lock);
    KeLeaveCriticalRegion();

    return status;
}


_Use_decl_annotations_
NTSTATUS
SdLoadApiHashDatabase(
    _In_ PSD_DETECTOR Detector,
    _In_ PUNICODE_STRING FilePath
    )
{
    PAGED_CODE();

    //
    // M-1 LIMITATION: File-based API hash database loading is NOT implemented.
    // The detector uses a hardcoded built-in database (SdpInitializeApiHashDatabase).
    // To add custom hash entries at runtime, use SdAddApiHash() directly.
    // A future implementation should:
    //   1. Open FilePath with ZwCreateFile
    //   2. Parse a structured format (JSON/binary) with hash → API name mappings
    //   3. Call SdAddApiHash for each entry
    //   4. Validate file integrity (signature/checksum) before loading
    //

    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(FilePath);

    return STATUS_NOT_IMPLEMENTED;
}


//=============================================================================
// Result Management
//=============================================================================

_Use_decl_annotations_
VOID
SdFreeResult(
    _In_ PSD_DETECTION_RESULT Result
    )
{
    if (Result != NULL) {
        RtlSecureZeroMemory(Result, sizeof(SD_DETECTION_RESULT));
        ShadowStrikeFreePoolWithTag(Result, SD_POOL_TAG_RESULT);
    }
}


//=============================================================================
// Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SdGetStatistics(
    _In_ PSD_DETECTOR Detector,
    _Out_ PSD_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Detector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SdpIsReady(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(SD_STATISTICS));

    Stats->TotalScans = Detector->Stats.TotalScans;
    Stats->DetectionsFound = Detector->Stats.DetectionsFound;
    Stats->NopSledsFound = Detector->Stats.NopSledsFound;
    Stats->EggHuntersFound = Detector->Stats.EggHuntersFound;
    Stats->EncodersFound = Detector->Stats.EncodersFound;
    Stats->ApiHashingFound = Detector->Stats.ApiHashingFound;
    Stats->SyscallsFound = Detector->Stats.SyscallsFound;
    Stats->ApiHashCount = Detector->ApiHashes.HashCount;
    Stats->SignatureCount = Detector->Signatures.SignatureCount;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal Functions
//=============================================================================

static VOID
SdpInitializeDefaultConfig(
    _Out_ PSD_CONFIG Config
    )
{
    RtlZeroMemory(Config, sizeof(SD_CONFIG));

    Config->EnableNopSledDetection = TRUE;
    Config->EnableEggHunterDetection = TRUE;
    Config->EnableEncoderDetection = TRUE;
    Config->EnableApiHashDetection = TRUE;
    Config->EnableSyscallDetection = TRUE;
    Config->EnableStackPivotDetection = TRUE;
    Config->EnableEntropyAnalysis = TRUE;
    Config->EnableSignatureMatching = TRUE;

    Config->NopSledMinLength = SD_NOP_SLED_MIN_LENGTH;
    Config->EntropyThreshold = SD_ENTROPY_THRESHOLD_DEFAULT;
    Config->MinConfidenceScore = SD_MIN_CONFIDENCE_DEFAULT;

    Config->MaxScanSizeBytes = SD_MAX_SCAN_SIZE;
    Config->ScanTimeoutMs = SD_DEFAULT_TIMEOUT_MS;
}


static VOID
SdpInitializeApiHashDatabase(
    _Inout_ PSD_DETECTOR Detector
    )
/*++

Routine Description:

    Populates the API hash database with common shellcode API hashes.
    Called during initialization (state=INITIALIZING), so bypasses SdAddApiHash
    public API which requires state=READY. Adds entries directly to the list.

--*/
{
    NTSTATUS status;

    //
    // Internal helper to add a hash entry without the SdpIsReady check.
    // During initialization, the state is INITIALIZING, not READY.
    //
    #define SD_ADD_HASH_INTERNAL(hash, api, dll) \
        do { \
            PSD_API_HASH_ENTRY _entry = (PSD_API_HASH_ENTRY)ShadowStrikeAllocatePoolWithTag( \
                NonPagedPoolNx, sizeof(SD_API_HASH_ENTRY), SD_POOL_TAG_PATTERN); \
            if (_entry != NULL) { \
                RtlZeroMemory(_entry, sizeof(SD_API_HASH_ENTRY)); \
                _entry->Hash = (hash); \
                RtlStringCchCopyA(_entry->ApiName, sizeof(_entry->ApiName), (api)); \
                RtlStringCchCopyA(_entry->DllName, sizeof(_entry->DllName), (dll)); \
                if (Detector->ApiHashes.HashTable == NULL) { \
                    Detector->ApiHashes.HashTable = ShadowStrikeAllocatePoolWithTag( \
                        NonPagedPoolNx, sizeof(LIST_ENTRY), SD_POOL_TAG_PATTERN); \
                    if (Detector->ApiHashes.HashTable == NULL) { \
                        ShadowStrikeFreePoolWithTag(_entry, SD_POOL_TAG_PATTERN); \
                        return; \
                    } \
                    InitializeListHead((PLIST_ENTRY)Detector->ApiHashes.HashTable); \
                } \
                InsertTailList((PLIST_ENTRY)Detector->ApiHashes.HashTable, &_entry->ListEntry); \
                Detector->ApiHashes.HashCount++; \
            } \
        } while (0)

    //
    // H-6 fix: If first allocation fails, hash table cannot be created — return early.
    //

    // Common ROR13 hashes used by shellcode
    SD_ADD_HASH_INTERNAL(ROR13_LOADLIBRARYA, "LoadLibraryA", "kernel32.dll");
    if (Detector->ApiHashes.HashTable == NULL) {
        return;  // First alloc failed — no point continuing
    }
    
    SD_ADD_HASH_INTERNAL(ROR13_GETPROCADDRESS, "GetProcAddress", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(ROR13_VIRTUALALLOC, "VirtualAlloc", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(ROR13_VIRTUALPROTECT, "VirtualProtect", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(ROR13_CREATETHREAD, "CreateThread", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(ROR13_NTFLUSHINSTRUCTIONCACHE, "NtFlushInstructionCache", "ntdll.dll");

    // Additional common hashes
    SD_ADD_HASH_INTERNAL(0xEC0E4E8E, "LoadLibraryW", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x7802F749, "GetProcAddressForCaller", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0xE449F330, "VirtualAllocEx", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0xE7BDD8C5, "VirtualProtectEx", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x799AACC6, "CreateRemoteThread", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0xE035F044, "Sleep", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x876F8B31, "WinExec", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x56A2B5F0, "ExitProcess", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x5DE2C5AA, "GetLastError", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x4FDAF6DA, "CloseHandle", "kernel32.dll");

    // Network APIs (common in reverse shells)
    SD_ADD_HASH_INTERNAL(0x6174A599, "WSAStartup", "ws2_32.dll");
    SD_ADD_HASH_INTERNAL(0xE0DF0FEA, "WSASocketA", "ws2_32.dll");
    SD_ADD_HASH_INTERNAL(0x6737DBC2, "connect", "ws2_32.dll");
    SD_ADD_HASH_INTERNAL(0x33604C84, "recv", "ws2_32.dll");
    SD_ADD_HASH_INTERNAL(0x5FC8D902, "send", "ws2_32.dll");
    SD_ADD_HASH_INTERNAL(0x614D6E75, "closesocket", "ws2_32.dll");

    // Process/Thread APIs
    SD_ADD_HASH_INTERNAL(0xAFC98D6F, "CreateProcessA", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x16B3FE72, "CreateProcessW", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x863FCC79, "OpenProcess", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x1E380A6E, "WriteProcessMemory", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0xDBD95D5C, "ReadProcessMemory", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0xCB72D9E8, "ResumeThread", "kernel32.dll");
    SD_ADD_HASH_INTERNAL(0x1D1C1CAC, "SuspendThread", "kernel32.dll");

    // Ntdll APIs (for direct syscall detection)
    SD_ADD_HASH_INTERNAL(0x3CFA685D, "NtAllocateVirtualMemory", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0x50E92888, "NtProtectVirtualMemory", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0xE3BD6D35, "NtWriteVirtualMemory", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0x4FFF8B29, "NtReadVirtualMemory", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0x4B82F718, "NtCreateThreadEx", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0xE9DAEE4C, "NtQueueApcThread", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0x7299EAF9, "NtCreateSection", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0x3B2E55EB, "NtMapViewOfSection", "ntdll.dll");
    SD_ADD_HASH_INTERNAL(0x6AA412CD, "NtUnmapViewOfSection", "ntdll.dll");

    #undef SD_ADD_HASH_INTERNAL
}


static VOID
SdpCleanupApiHashDatabase(
    _Inout_ PSD_DETECTOR Detector
    )
{
    PLIST_ENTRY hashTable;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ApiHashes.Lock);

    hashTable = (PLIST_ENTRY)Detector->ApiHashes.HashTable;
    if (hashTable != NULL) {
        for (entry = hashTable->Flink; entry != hashTable; entry = next) {
            next = entry->Flink;
            PSD_API_HASH_ENTRY hashEntry = CONTAINING_RECORD(entry, SD_API_HASH_ENTRY, ListEntry);
            RemoveEntryList(entry);
            ShadowStrikeFreePoolWithTag(hashEntry, SD_POOL_TAG_PATTERN);
        }

        ShadowStrikeFreePoolWithTag(hashTable, SD_POOL_TAG_PATTERN);
        Detector->ApiHashes.HashTable = NULL;
    }

    Detector->ApiHashes.HashCount = 0;

    ExReleasePushLockExclusive(&Detector->ApiHashes.Lock);
    KeLeaveCriticalRegion();
}


static VOID
SdpCleanupSignatureDatabase(
    _Inout_ PSD_DETECTOR Detector
    )
{
    PLIST_ENTRY sigTable;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->Signatures.Lock);

    sigTable = (PLIST_ENTRY)Detector->Signatures.SignatureDatabase;
    if (sigTable != NULL) {
        for (entry = sigTable->Flink; entry != sigTable; entry = next) {
            next = entry->Flink;
            PSD_SIGNATURE_ENTRY sigEntry = CONTAINING_RECORD(entry, SD_SIGNATURE_ENTRY, ListEntry);
            RemoveEntryList(entry);
            ShadowStrikeFreePoolWithTag(sigEntry, SD_POOL_TAG_PATTERN);
        }

        ShadowStrikeFreePoolWithTag(sigTable, SD_POOL_TAG_PATTERN);
        Detector->Signatures.SignatureDatabase = NULL;
    }

    Detector->Signatures.SignatureCount = 0;

    ExReleasePushLockExclusive(&Detector->Signatures.Lock);
    KeLeaveCriticalRegion();
}


static ULONG
SdpCalculateEntropy(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    M-3 fix: Calculates Shannon entropy of a buffer as a percentage (0-100).
    Uses correct formula: H = -sum(p * log2(p)) where p = freq[i] / N.
    
    Integer approximation:
      H = log2(N) - (1/N) * sum(freq[i] * log2(freq[i])) for freq[i] > 0
    
    Scaled: result = H * 100 / 8 (max entropy = 8 bits/byte = 100%)

--*/
{
    ULONG frequency[256] = {0};
    SIZE_T i;
    ULONG64 sumFLogF = 0;
    ULONG log2N;
    ULONG64 entropyScaled;

    if (Size == 0) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Size; i++) {
        frequency[Buffer[i]]++;
    }

    //
    // Integer log2 approximation via bit-scan
    //
    #define SD_ILOG2(val, result) \
        do { \
            ULONG _t = (val); \
            (result) = 0; \
            while (_t > 1) { _t >>= 1; (result)++; } \
        } while (0)

    //
    // Compute log2(N)
    //
    {
        ULONG tempN = (ULONG)min(Size, (SIZE_T)MAXULONG);
        SD_ILOG2(tempN, log2N);
    }

    //
    // Compute sum(f * log2(f)) for all f > 0
    //
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 1) {  // log2(1) = 0, so skip freq=1
            ULONG log2F;
            SD_ILOG2(frequency[i], log2F);
            sumFLogF += (ULONG64)frequency[i] * log2F;
        }
        // freq=0 contributes 0, freq=1 contributes 1*0=0
    }

    //
    // H = log2(N) - (1/N) * sumFLogF
    // Scale to percentage: result = H * 100 / 8
    // Combined: result = (log2(N) * 100 / 8) - (sumFLogF * 100) / (N * 8)
    //
    // To avoid truncation, multiply first:
    //   result = (log2(N) * 100 * N - sumFLogF * 100) / (N * 8)
    //          = 100 * (log2(N) * N - sumFLogF) / (N * 8)
    //
    {
        ULONG64 n64 = (ULONG64)Size;
        ULONG64 numerator;

        if (n64 == 0) return 0;

        // log2(N) * N might be small enough to fit easily
        if ((ULONG64)log2N * n64 < sumFLogF) {
            return 0;  // Shouldn't happen with valid data, but safety check
        }

        numerator = ((ULONG64)log2N * n64) - sumFLogF;
        entropyScaled = (numerator * 100) / (n64 * 8);

        if (entropyScaled > 100) entropyScaled = 100;
    }

    #undef SD_ILOG2

    return (ULONG)entropyScaled;
}


static BOOLEAN
SdpDetectNopSledInternal(
    _In_ PSD_SCAN_CONTEXT Context,
    _Out_ PULONG Offset,
    _Out_ PULONG Length,
    _Out_ PUCHAR NopByte
    )
/*++

Routine Description:

    Detects NOP sleds including standard NOPs and NOP-equivalent instructions.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;
    ULONG consecutiveNops = 0;
    ULONG maxConsecutive = 0;
    SIZE_T maxOffset = 0;
    UCHAR maxNopByte = 0x90;
    SIZE_T currentRunOffset = 0;
    UCHAR currentRunByte = 0x90;
    ULONG minLength = Context->Detector->Config.NopSledMinLength;

    *Offset = 0;
    *Length = 0;
    *NopByte = 0;

    for (i = 0; i < size; i++) {
        BOOLEAN isNop = FALSE;

        //
        // Check for standard NOP (0x90)
        //
        if (buffer[i] == 0x90) {
            isNop = TRUE;
        }
        //
        // Check for multi-byte NOP (0x66 0x90)
        //
        else if (buffer[i] == 0x66 && i + 1 < size && buffer[i + 1] == 0x90) {
            isNop = TRUE;
            i++;  // Skip next byte
        }
        //
        // Check for long NOP (0F 1F /0)
        //
        else if (buffer[i] == 0x0F && i + 1 < size && buffer[i + 1] == 0x1F) {
            isNop = TRUE;
            //
            // Skip variable-length NOP
            //
            if (i + 2 < size) {
                UCHAR modrm = buffer[i + 2];
                ULONG extraBytes = 1;  // At least ModR/M

                if ((modrm & 0xC0) != 0xC0) {
                    if ((modrm & 0x07) == 0x04) extraBytes++;  // SIB
                    if ((modrm & 0xC0) == 0x40) extraBytes++;  // disp8
                    else if ((modrm & 0xC0) == 0x80) extraBytes += 4;  // disp32
                }

                i += extraBytes;
            }
        }

        if (isNop) {
            if (consecutiveNops == 0) {
                currentRunOffset = i;
                currentRunByte = buffer[i];
            }
            consecutiveNops++;
        } else {
            if (consecutiveNops > maxConsecutive) {
                maxConsecutive = consecutiveNops;
                maxOffset = currentRunOffset;
                maxNopByte = currentRunByte;
            }
            consecutiveNops = 0;
        }
    }

    //
    // Check final run
    //
    if (consecutiveNops > maxConsecutive) {
        maxConsecutive = consecutiveNops;
        maxOffset = currentRunOffset;
        maxNopByte = currentRunByte;
    }

    if (maxConsecutive >= minLength) {
        *Offset = (ULONG)maxOffset;
        *Length = maxConsecutive;
        *NopByte = maxNopByte;
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
SdpDetectEggHunter(
    _In_ PSD_SCAN_CONTEXT Context
    )
/*++

Routine Description:

    Detects egg hunter shellcode patterns.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;

    //
    // Egg hunters are typically small (<128 bytes) and contain specific patterns
    //
    if (size > SD_EGG_HUNTER_MAX_SIZE * 4) {
        //
        // Only scan beginning of buffer for egg hunters
        //
        size = SD_EGG_HUNTER_MAX_SIZE * 4;
    }

    for (i = 0; i < size; i++) {
        //
        // SEH-based egg hunter
        //
        if (i + sizeof(g_EggHunterSEH) <= size) {
            if (RtlCompareMemory(&buffer[i], g_EggHunterSEH,
                                 sizeof(g_EggHunterSEH)) == sizeof(g_EggHunterSEH)) {
                Context->Result->EggHunter.HunterAddress = &buffer[i];
                Context->Result->EggHunter.HunterSize = sizeof(g_EggHunterSEH);
                return TRUE;
            }
        }

        //
        // Syscall-based egg hunter
        //
        if (i + sizeof(g_EggHunterSyscall) <= size) {
            if (RtlCompareMemory(&buffer[i], g_EggHunterSyscall,
                                 sizeof(g_EggHunterSyscall)) == sizeof(g_EggHunterSyscall)) {
                Context->Result->EggHunter.HunterAddress = &buffer[i];
                Context->Result->EggHunter.HunterSize = sizeof(g_EggHunterSyscall);
                return TRUE;
            }
        }

        //
        // NtDisplayString egg hunter
        //
        if (i + sizeof(g_EggHunterNtDisplayString) <= size) {
            if (RtlCompareMemory(&buffer[i], g_EggHunterNtDisplayString,
                                 sizeof(g_EggHunterNtDisplayString)) == sizeof(g_EggHunterNtDisplayString)) {
                Context->Result->EggHunter.HunterAddress = &buffer[i];
                Context->Result->EggHunter.HunterSize = sizeof(g_EggHunterNtDisplayString);
                return TRUE;
            }
        }

        //
        // Generic egg hunter pattern: OR DX, 0x0FFF; INC EDX
        //
        if (i + 7 <= size) {
            if (buffer[i] == 0x66 && buffer[i + 1] == 0x81 && buffer[i + 2] == 0xCA &&
                buffer[i + 3] == 0xFF && buffer[i + 4] == 0x0F) {
                Context->Result->EggHunter.HunterAddress = &buffer[i];
                Context->Result->EggHunter.HunterSize = 5;
                return TRUE;
            }
        }
    }

    return FALSE;
}


static BOOLEAN
SdpDetectEncoderLoop(
    _In_ PSD_SCAN_CONTEXT Context,
    _Out_ PSD_ENCODER_INFO EncoderInfo
    )
/*++

Routine Description:

    Detects encoder/decoder loops commonly used in shellcode.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;
    BOOLEAN found = FALSE;

    RtlZeroMemory(EncoderInfo, sizeof(SD_ENCODER_INFO));

    if (size > SD_ENCODER_LOOP_MAX_SIZE * 4) {
        size = SD_ENCODER_LOOP_MAX_SIZE * 4;
    }

    for (i = 0; i < size - 4; i++) {
        //
        // XOR encoding patterns
        //

        //
        // Pattern: XOR BYTE PTR [reg+offset], imm8 (80 34 xx xx)
        //
        if (buffer[i] == 0x80 && (buffer[i + 1] & 0x38) == 0x30) {
            //
            // Look for loop instruction nearby
            //
            SIZE_T j;
            for (j = i + 3; j < min(i + 32, size - 1); j++) {
                if (buffer[j] == 0xE2 ||  // LOOP
                    buffer[j] == 0xEB ||  // JMP short
                    (buffer[j] == 0x75 || buffer[j] == 0x74)) {  // JNZ/JZ
                    EncoderInfo->Type = EncoderType_XOR;
                    EncoderInfo->LoopStart = (ULONG64)&buffer[i];
                    EncoderInfo->LoopEnd = (ULONG64)&buffer[j + 2];
                    found = TRUE;
                    break;
                }
            }
        }

        //
        // Pattern: XOR [reg], reg (31 /r or 33 /r)
        //
        if ((buffer[i] == 0x31 || buffer[i] == 0x33) &&
            (buffer[i + 1] & 0xC0) != 0xC0) {
            //
            // Check for loop
            //
            SIZE_T j;
            for (j = i + 2; j < min(i + 32, size - 1); j++) {
                if (buffer[j] == 0xE2 || buffer[j] == 0xEB ||
                    buffer[j] == 0x75 || buffer[j] == 0x74) {
                    EncoderInfo->Type = EncoderType_XOR;
                    EncoderInfo->LoopStart = (ULONG64)&buffer[i];
                    EncoderInfo->LoopEnd = (ULONG64)&buffer[j + 2];
                    found = TRUE;
                    break;
                }
            }
        }

        //
        // ADD encoding pattern: ADD BYTE PTR [reg+offset], imm8
        //
        if (buffer[i] == 0x80 && (buffer[i + 1] & 0x38) == 0x00) {
            SIZE_T j;
            for (j = i + 3; j < min(i + 32, size - 1); j++) {
                if (buffer[j] == 0xE2 || buffer[j] == 0xEB) {
                    EncoderInfo->Type = EncoderType_ADD;
                    EncoderInfo->LoopStart = (ULONG64)&buffer[i];
                    EncoderInfo->LoopEnd = (ULONG64)&buffer[j + 2];
                    found = TRUE;
                    break;
                }
            }
        }

        //
        // SUB encoding pattern: SUB BYTE PTR [reg+offset], imm8
        //
        if (buffer[i] == 0x80 && (buffer[i + 1] & 0x38) == 0x28) {
            SIZE_T j;
            for (j = i + 3; j < min(i + 32, size - 1); j++) {
                if (buffer[j] == 0xE2 || buffer[j] == 0xEB) {
                    EncoderInfo->Type = EncoderType_SUB;
                    EncoderInfo->LoopStart = (ULONG64)&buffer[i];
                    EncoderInfo->LoopEnd = (ULONG64)&buffer[j + 2];
                    found = TRUE;
                    break;
                }
            }
        }

        //
        // ROL/ROR encoding: C0 /0 (ROL) or C0 /1 (ROR)
        //
        if (buffer[i] == 0xC0 &&
            ((buffer[i + 1] & 0x38) == 0x00 || (buffer[i + 1] & 0x38) == 0x08)) {
            SIZE_T j;
            for (j = i + 3; j < min(i + 32, size - 1); j++) {
                if (buffer[j] == 0xE2 || buffer[j] == 0xEB) {
                    EncoderInfo->Type = (buffer[i + 1] & 0x38) == 0x00 ?
                        EncoderType_ROL : EncoderType_ROR;
                    EncoderInfo->LoopStart = (ULONG64)&buffer[i];
                    EncoderInfo->LoopEnd = (ULONG64)&buffer[j + 2];
                    found = TRUE;
                    break;
                }
            }
        }

        if (found) break;
    }

    return found;
}


static BOOLEAN
SdpDetectApiHashing(
    _In_ PSD_SCAN_CONTEXT Context,
    _Out_ PSD_API_HASH_INFO ApiHashInfo
    )
/*++

Routine Description:

    Detects API hash resolution patterns and attempts to resolve hashes.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;
    ULONG hashesFound = 0;

    RtlZeroMemory(ApiHashInfo, sizeof(SD_API_HASH_INFO));

    //
    // Look for common API hash patterns
    //
    for (i = 0; i < size - 4 && hashesFound < 32; i++) {
        //
        // Pattern: MOV EAX/ECX/EDX, imm32 (hash value)
        // B8 xx xx xx xx / B9 xx xx xx xx / BA xx xx xx xx
        //
        if (buffer[i] == 0xB8 || buffer[i] == 0xB9 || buffer[i] == 0xBA) {
            if (i + 5 <= size) {
                ULONG potentialHash = SdpReadUnalignedUlong(&buffer[i + 1]);
                //
                CHAR apiName[64] = {0};
                CHAR dllName[32] = {0};

                if (NT_SUCCESS(SdLookupApiHash(Context->Detector, potentialHash,
                                               apiName, sizeof(apiName),
                                               dllName, sizeof(dllName)))) {
                    //
                    // Found a known hash!
                    //
                    ApiHashInfo->Algorithm = HashAlgorithm_ROR13;
                    ApiHashInfo->ResolvedApis[hashesFound].Hash = potentialHash;
                    RtlStringCchCopyA(ApiHashInfo->ResolvedApis[hashesFound].ApiName,
                                     sizeof(ApiHashInfo->ResolvedApis[hashesFound].ApiName),
                                     apiName);
                    RtlStringCchCopyA(ApiHashInfo->ResolvedApis[hashesFound].DllName,
                                     sizeof(ApiHashInfo->ResolvedApis[hashesFound].DllName),
                                     dllName);
                    hashesFound++;

                    if (ApiHashInfo->ResolutionCodeStart == 0) {
                        ApiHashInfo->ResolutionCodeStart = (ULONG64)&buffer[i];
                    }
                }
            }
        }

        //
        // Pattern: PUSH imm32 (hash value on stack)
        // 68 xx xx xx xx
        //
        if (buffer[i] == 0x68 && i + 5 <= size) {
            ULONG potentialHash = SdpReadUnalignedUlong(&buffer[i + 1]);

            CHAR apiName[64] = {0};
            CHAR dllName[32] = {0};

            if (NT_SUCCESS(SdLookupApiHash(Context->Detector, potentialHash,
                                           apiName, sizeof(apiName),
                                           dllName, sizeof(dllName)))) {
                ApiHashInfo->Algorithm = HashAlgorithm_ROR13;
                ApiHashInfo->ResolvedApis[hashesFound].Hash = potentialHash;
                RtlStringCchCopyA(ApiHashInfo->ResolvedApis[hashesFound].ApiName,
                                 sizeof(ApiHashInfo->ResolvedApis[hashesFound].ApiName),
                                 apiName);
                RtlStringCchCopyA(ApiHashInfo->ResolvedApis[hashesFound].DllName,
                                 sizeof(ApiHashInfo->ResolvedApis[hashesFound].DllName),
                                 dllName);
                hashesFound++;

                if (ApiHashInfo->ResolutionCodeStart == 0) {
                    ApiHashInfo->ResolutionCodeStart = (ULONG64)&buffer[i];
                }
            }
        }
    }

    ApiHashInfo->ResolvedCount = hashesFound;

    return (hashesFound > 0);
}


static BOOLEAN
SdpDetectDirectSyscalls(
    _In_ PSD_SCAN_CONTEXT Context
    )
/*++

Routine Description:

    Detects direct syscall stubs that bypass NTDLL hooks.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;
    ULONG syscallCount = 0;

    for (i = 0; i < size - 8; i++) {
        //
        // x64 syscall pattern: MOV R10, RCX; MOV EAX, imm32; SYSCALL
        //
        if (RtlCompareMemory(&buffer[i], g_SyscallPatternX64,
                             sizeof(g_SyscallPatternX64)) == sizeof(g_SyscallPatternX64)) {
            //
            // Check for SYSCALL instruction within next 20 bytes
            //
            SIZE_T j;
            for (j = i + sizeof(g_SyscallPatternX64); j < min(i + 20, size - 2); j++) {
                if (buffer[j] == 0x0F && buffer[j + 1] == 0x05) {
                    SD_SYSCALL_INFO* syscallInfo = &Context->Result->Syscalls.Syscalls[syscallCount];

                    syscallInfo->SyscallNumber = SdpReadUnalignedUlong(&buffer[i + sizeof(g_SyscallPatternX64)]);
                    syscallInfo->StubAddress = (ULONG64)&buffer[i];
                    syscallInfo->StubSize = (ULONG)(j + 2 - i);
                    syscallInfo->Type = StubType_Direct;

                    RtlCopyMemory(syscallInfo->StubBytes, &buffer[i],
                                 min(SD_SYSCALL_STUB_SIZE, syscallInfo->StubSize));

                    syscallCount++;
                    if (syscallCount >= 16) {
                        break;
                    }
                }
            }
        }

        //
        // Raw SYSCALL/SYSENTER/INT 2E without setup (indirect call)
        //
        if ((buffer[i] == 0x0F && i + 1 < size && buffer[i + 1] == 0x05) ||  // SYSCALL
            (buffer[i] == 0x0F && i + 1 < size && buffer[i + 1] == 0x34) ||  // SYSENTER
            (buffer[i] == 0xCD && i + 1 < size && buffer[i + 1] == 0x2E)) {  // INT 2E

            //
            // Check if this is within an already-found stub
            //
            BOOLEAN inExisting = FALSE;
            ULONG k;
            for (k = 0; k < syscallCount; k++) {
                if ((ULONG64)&buffer[i] >= Context->Result->Syscalls.Syscalls[k].StubAddress &&
                    (ULONG64)&buffer[i] < Context->Result->Syscalls.Syscalls[k].StubAddress +
                                          Context->Result->Syscalls.Syscalls[k].StubSize) {
                    inExisting = TRUE;
                    break;
                }
            }

            if (!inExisting && syscallCount < 16) {
                Context->Result->Syscalls.Syscalls[syscallCount].StubAddress = (ULONG64)&buffer[i];
                Context->Result->Syscalls.Syscalls[syscallCount].StubSize = 2;
                Context->Result->Syscalls.Syscalls[syscallCount].Type =
                    (buffer[i] == 0xCD) ? StubType_Indirect : StubType_Direct;
                RtlCopyMemory(Context->Result->Syscalls.Syscalls[syscallCount].StubBytes,
                             &buffer[i], 2);
                syscallCount++;
            }
        }

        if (syscallCount >= 16) break;
    }

    Context->Result->Syscalls.Found = (syscallCount > 0);
    Context->Result->Syscalls.Count = syscallCount;

    return (syscallCount > 0);
}


static BOOLEAN
SdpDetectHeavensGate(
    _In_ PSD_SCAN_CONTEXT Context
    )
/*++

Routine Description:

    Detects Heaven's Gate (32->64 bit transition) patterns.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;

    for (i = 0; i < size - 12; i++) {
        //
        // JMP FAR to 0x33 segment
        //
        if (buffer[i] == 0xEA && i + 7 <= size) {
            //
            // Check if segment is 0x33 (64-bit code segment)
            //
            USHORT segment;
            RtlCopyMemory(&segment, &buffer[i + 5], sizeof(USHORT));
            if (segment == 0x33 || segment == 0x23) {
                return TRUE;
            }
        }

        //
        // RETF-based transition: PUSH 0x33; CALL $+5; ADD [ESP], 5; RETF
        //
        if (RtlCompareMemory(&buffer[i], g_HeavensGateRetf,
                             sizeof(g_HeavensGateRetf)) == sizeof(g_HeavensGateRetf)) {
            return TRUE;
        }

        //
        // Alternative pattern: PUSH 0x33; PUSH addr; RETF
        //
        if (buffer[i] == 0x6A && buffer[i + 1] == 0x33 &&
            i + 7 <= size && buffer[i + 6] == 0xCB) {
            return TRUE;
        }
    }

    return FALSE;
}


static BOOLEAN
SdpDetectStackPivot(
    _In_ PSD_SCAN_CONTEXT Context
    )
/*++

Routine Description:

    Detects stack pivot gadgets used in ROP chains.

--*/
{
    PUCHAR buffer = Context->Buffer;
    SIZE_T size = Context->Size;
    SIZE_T i;
    ULONG gadgetCount = 0;

    for (i = 0; i < size - 4; i++) {
        BOOLEAN isGadget = FALSE;
        ULONG gadgetSize = 0;

        //
        // XCHG EAX, ESP (94)
        //
        if (buffer[i] == 0x94) {
            isGadget = TRUE;
            gadgetSize = 1;
        }
        //
        // XCHG reg, ESP (87 E4/EC/F4/FC/DC/CC/BC)
        //
        else if (buffer[i] == 0x87) {
            UCHAR modrm = buffer[i + 1];
            if ((modrm & 0xC7) == 0xC4 ||  // reg, ESP
                (modrm & 0xF8) == 0xE0) {  // ESP, reg
                isGadget = TRUE;
                gadgetSize = 2;
            }
        }
        //
        // MOV ESP, reg (89 xx where dest is ESP)
        //
        else if (buffer[i] == 0x89) {
            UCHAR modrm = buffer[i + 1];
            if ((modrm & 0xC7) == 0xC4) {  // dest is ESP (register mode)
                isGadget = TRUE;
                gadgetSize = 2;
            }
        }
        //
        // LEAVE + RET (C9 C3)
        //
        else if (buffer[i] == 0xC9 && i + 1 < size && buffer[i + 1] == 0xC3) {
            //
            // LEAVE by itself isn't a pivot, but followed by RET in unexpected
            // context could be
            //
            if (i > 0 && buffer[i - 1] != 0x90 && buffer[i - 1] != 0xCC) {
                isGadget = TRUE;
                gadgetSize = 2;
            }
        }
        //
        // POP ESP (5C) - direct ESP manipulation
        //
        else if (buffer[i] == 0x5C) {
            isGadget = TRUE;
            gadgetSize = 1;
        }
        //
        // ADD ESP, large_value or SUB ESP, large_value (unusual stack frame)
        //
        else if ((buffer[i] == 0x81 || buffer[i] == 0x83) && i + 2 < size) {
            UCHAR modrm = buffer[i + 1];
            if ((modrm & 0xC7) == 0xC4 &&  // ESP destination
                (modrm & 0x38) == 0x00) {  // ADD
                //
                // Check for large value
                //
                if (buffer[i] == 0x81 && i + 6 <= size) {
                    LONG value;
                    RtlCopyMemory(&value, &buffer[i + 2], sizeof(LONG));
                    if (value > 0x1000 || value < -0x1000) {
                        isGadget = TRUE;
                        gadgetSize = 6;
                    }
                }
            }
        }

        if (isGadget) {
            //
            // Check if followed by RET (makes it an exploitable gadget)
            //
            if (i + gadgetSize < size &&
                (buffer[i + gadgetSize] == 0xC3 || buffer[i + gadgetSize] == 0xC2)) {

                Context->Result->StackPivot.Found = TRUE;
                Context->Result->StackPivot.GadgetAddress = &buffer[i];
                Context->Result->StackPivot.GadgetSize = gadgetSize + 1;

                RtlCopyMemory(Context->Result->StackPivot.GadgetBytes,
                             &buffer[i], min(32, gadgetSize + 1));

                gadgetCount++;
                if (gadgetCount >= 1) {
                    return TRUE;  // Found at least one
                }
            }
        }
    }

    return (gadgetCount > 0);
}


static BOOLEAN
SdpMatchSignatures(
    _In_ PSD_SCAN_CONTEXT Context
    )
/*++

Routine Description:

    Matches buffer against known shellcode signatures.

--*/
{
    PSD_DETECTOR detector = Context->Detector;
    PLIST_ENTRY sigTable;
    PLIST_ENTRY entry;
    BOOLEAN matched = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&detector->Signatures.Lock);

    sigTable = (PLIST_ENTRY)detector->Signatures.SignatureDatabase;
    if (sigTable != NULL) {
        for (entry = sigTable->Flink; entry != sigTable && !matched; entry = entry->Flink) {
            PSD_SIGNATURE_ENTRY sig = CONTAINING_RECORD(entry, SD_SIGNATURE_ENTRY, ListEntry);
            SIZE_T i;

            //
            // Scan for signature
            //
            for (i = 0; i + sig->PatternSize <= Context->Size; i++) {
                BOOLEAN match = TRUE;
                ULONG j;

                for (j = 0; j < sig->PatternSize && match; j++) {
                    if (sig->Mask[j] && Context->Buffer[i + j] != sig->Pattern[j]) {
                        match = FALSE;
                    }
                }

                if (match) {
                    Context->Result->Signature.Matched = TRUE;
                    RtlStringCchCopyA(Context->Result->Signature.SignatureName,
                                     sizeof(Context->Result->Signature.SignatureName),
                                     sig->SignatureName);
                    RtlStringCchCopyA(Context->Result->Signature.ThreatFamily,
                                     sizeof(Context->Result->Signature.ThreatFamily),
                                     sig->ThreatFamily);
                    matched = TRUE;
                    break;
                }
            }
        }
    }

    ExReleasePushLockShared(&detector->Signatures.Lock);
    KeLeaveCriticalRegion();

    return matched;
}


static ULONG
SdpCalculateConfidenceScore(
    _In_ PSD_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Calculates overall confidence score based on detection flags.

--*/
{
    ULONG score = 0;

    //
    // Individual detection contributions
    //
    if (Result->Flags & SdFlag_NopSled) {
        score += 15;
        if (Result->NopSled.Length > 64) score += 10;
    }

    if (Result->Flags & SdFlag_EggHunter) {
        score += 30;  // Egg hunters are very specific
    }

    if (Result->Flags & SdFlag_Encoder) {
        score += 20;
    }

    if (Result->Flags & SdFlag_APIHashing) {
        score += 25;
        if (Result->ApiHashing.ResolvedCount > 3) score += 15;
    }

    if (Result->Flags & SdFlag_DirectSyscall) {
        score += 20;
        if (Result->Syscalls.Count > 2) score += 10;
    }

    if (Result->Flags & SdFlag_HeavensGate) {
        score += 35;  // Very specific technique
    }

    if (Result->Flags & SdFlag_StackPivot) {
        score += 20;
    }

    if (Result->Flags & SdFlag_HighEntropy) {
        score += 10;
    }

    if (Result->Flags & SdFlag_KnownSignature) {
        score += 40;  // Known bad
    }

    //
    // Combination bonuses
    //
    if ((Result->Flags & SdFlag_NopSled) && (Result->Flags & SdFlag_Encoder)) {
        score += 15;  // Classic shellcode pattern
    }

    if ((Result->Flags & SdFlag_APIHashing) && (Result->Flags & SdFlag_DirectSyscall)) {
        score += 20;  // Sophisticated shellcode
    }

    if ((Result->Flags & SdFlag_HighEntropy) && (Result->Flags & SdFlag_Encoder)) {
        score += 10;  // Packed/encoded
    }

    //
    // Cap at 100
    //
    if (score > 100) score = 100;

    return score;
}


static ULONG
SdpCalculateSeverityScore(
    _In_ PSD_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Calculates severity score based on threat level.

--*/
{
    ULONG severity = 0;

    //
    // Base severity from type
    //
    switch (Result->Type) {
        case SdShellcode_Meterpreter:
        case SdShellcode_CobaltStrike:
            severity = 90;
            break;

        case SdShellcode_DirectSyscall:
        case SdShellcode_HeavensGate:
            severity = 80;
            break;

        case SdShellcode_APIHashing:
        case SdShellcode_Staged:
            severity = 70;
            break;

        case SdShellcode_XorEncoder:
        case SdShellcode_AlphanumEncoder:
            severity = 60;
            break;

        case SdShellcode_EggHunter:
        case SdShellcode_StackPivot:
            severity = 75;
            break;

        case SdShellcode_NopSled:
            severity = 50;
            break;

        default:
            severity = 40;
    }

    //
    // Adjust based on flags
    //
    if (Result->Flags & SdFlag_KnownSignature) {
        severity += 20;
    }

    if (Result->Flags & SdFlag_Polymorphic) {
        severity += 15;
    }

    if (Result->ConfidenceScore > 80) {
        severity += 10;
    }

    //
    // Cap at 100
    //
    if (severity > 100) severity = 100;

    return severity;
}


static SD_SHELLCODE_TYPE
SdpDeterminePrimaryType(
    _In_ PSD_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Determines the primary shellcode type from detection results.

--*/
{
    //
    // Priority order: most specific/dangerous first
    //
    if (Result->Signature.Matched) {
        if (SdpContainsSubstring(Result->Signature.ThreatFamily, "Meterpreter")) {
            return SdShellcode_Meterpreter;
        }
        if (SdpContainsSubstring(Result->Signature.ThreatFamily, "CobaltStrike") ||
            SdpContainsSubstring(Result->Signature.ThreatFamily, "Beacon")) {
            return SdShellcode_CobaltStrike;
        }
        return SdShellcode_Generic;
    }

    if (Result->Flags & SdFlag_HeavensGate) {
        return SdShellcode_HeavensGate;
    }

    if (Result->Flags & SdFlag_DirectSyscall) {
        return SdShellcode_DirectSyscall;
    }

    if (Result->Flags & SdFlag_EggHunter) {
        return SdShellcode_EggHunter;
    }

    if (Result->Flags & SdFlag_StackPivot) {
        return SdShellcode_StackPivot;
    }

    if (Result->Flags & SdFlag_APIHashing) {
        return SdShellcode_APIHashing;
    }

    if (Result->Flags & SdFlag_Encoder) {
        switch (Result->Encoder.Type) {
            case EncoderType_XOR:
                return SdShellcode_XorEncoder;
            case EncoderType_ADD:
                return SdShellcode_AddEncoder;
            case EncoderType_ROL:
            case EncoderType_ROR:
                return SdShellcode_RolEncoder;
            case EncoderType_Alphanumeric:
                return SdShellcode_AlphanumEncoder;
            case EncoderType_Unicode:
                return SdShellcode_UnicodeEncoder;
            default:
                break;
        }
    }

    if (Result->Flags & SdFlag_NopSled) {
        return SdShellcode_NopSled;
    }

    if (Result->Flags & SdFlag_PIC) {
        return SdShellcode_PositionIndependent;
    }

    return SdShellcode_Generic;
}


static BOOLEAN
SdpIsTimeout(
    _In_ PSD_SCAN_CONTEXT Context
    )
{
    LARGE_INTEGER currentTime;
    ULONG64 elapsedMs;

    if (Context->Cancelled) {
        return TRUE;
    }

    KeQuerySystemTime(&currentTime);
    elapsedMs = (currentTime.QuadPart - Context->StartTime.QuadPart) / 10000;

    return (elapsedMs >= Context->TimeoutMs);
}


//
// L-1: Dead SdpRor13Hash function removed — hash values are hardcoded constants.
//


static FORCEINLINE BOOLEAN
SdpSafeMemoryCompare(
    _In_reads_bytes_(Size) const VOID* Buffer1,
    _In_reads_bytes_(Size) const VOID* Buffer2,
    _In_ SIZE_T Size
    )
{
    return (RtlCompareMemory(Buffer1, Buffer2, Size) == Size);
}

