/*++
    ShadowStrike Next-Generation Antivirus
    Module: ROPDetector.c

    Purpose: Enterprise-grade Return-Oriented Programming (ROP) and
             Jump-Oriented Programming (JOP) attack detection engine.

    Architecture:
    - Stack frame analysis for ROP/JOP/COP chain detection
    - Gadget database with semantic analysis
    - Call stack validation and integrity checking
    - Control flow integrity (CFI) verification
    - Stack pivot detection
    - MITRE ATT&CK T1055.012 coverage

    Security Guarantees:
    - All memory accesses are validated before use
    - Integer overflow protection on all calculations
    - Thread-safe gadget database operations
    - Rate limiting to prevent resource exhaustion
    - Secure memory handling for sensitive data
    - Rundown protection for safe shutdown
    - Signature validation on all public API entries

    Copyright (c) ShadowStrike Team
--*/

#include "ROPDetector.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Utilities/HashUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, RopInitialize)
#pragma alloc_text(PAGE, RopShutdown)
#pragma alloc_text(PAGE, RopScanModuleForGadgets)
#pragma alloc_text(PAGE, RopAddGadget)
#pragma alloc_text(PAGE, RopLookupGadget)
#pragma alloc_text(PAGE, RopAnalyzeStack)
#pragma alloc_text(PAGE, RopAnalyzeStackBuffer)
#pragma alloc_text(PAGE, RopValidateCallStack)
#pragma alloc_text(PAGE, RopFreeResult)
#pragma alloc_text(PAGE, RopRegisterCallback)
#pragma alloc_text(PAGE, RopUnregisterCallback)
#pragma alloc_text(PAGE, RopGetStatistics)
#endif

//=============================================================================
// Private Constants
//=============================================================================

#define ROP_GADGET_HASH_BUCKETS         1024
#define ROP_MAX_CALLBACKS               16
#define ROP_STACK_ALIGNMENT             sizeof(ULONG_PTR)
#define ROP_MAX_CONSECUTIVE_GADGETS     64
#define ROP_ENTROPY_THRESHOLD           60
#define ROP_PIVOT_DISTANCE_THRESHOLD    0x10000
#define ROP_ANALYSIS_TIMEOUT_MS         5000
#define ROP_MAX_MODULES_TRACKED         256
#define ROP_GADGET_LOOKASIDE_DEPTH      512
#define ROP_KERNEL_STACK_SIZE_ESTIMATE  (24 * 1024)  // Conservative kernel stack estimate

//
// x86/x64 instruction opcodes for gadget detection
//
#define OPCODE_RET                      0xC3
#define OPCODE_RET_IMM16                0xC2
#define OPCODE_RETF                     0xCB
#define OPCODE_RETF_IMM16               0xCA
#define OPCODE_CALL_REL32               0xE8
#define OPCODE_JMP_REL32                0xE9
#define OPCODE_JMP_REL8                 0xEB
#define OPCODE_SYSCALL_0F               0x0F
#define OPCODE_SYSCALL_05               0x05
#define OPCODE_SYSENTER_0F              0x0F
#define OPCODE_SYSENTER_34              0x34
#define OPCODE_INT                      0xCD
#define OPCODE_FF_PREFIX                0xFF

//
// ModR/M byte analysis for CALL/JMP detection
//
#define MODRM_MOD_MASK                  0xC0
#define MODRM_REG_MASK                  0x38
#define MODRM_RM_MASK                   0x07
#define MODRM_REG_SHIFT                 3

#define FF_CALL_REG                     2   // CALL r/m
#define FF_CALL_MEM                     3   // CALL m16:32
#define FF_JMP_REG                      4   // JMP r/m
#define FF_JMP_MEM                      5   // JMP m16:32

//
// Register bit masks for semantic analysis
//
#define REG_RAX                         0x0001
#define REG_RCX                         0x0002
#define REG_RDX                         0x0004
#define REG_RBX                         0x0008
#define REG_RSP                         0x0010
#define REG_RBP                         0x0020
#define REG_RSI                         0x0040
#define REG_RDI                         0x0080
#define REG_R8                          0x0100
#define REG_R9                          0x0200
#define REG_R10                         0x0400
#define REG_R11                         0x0800
#define REG_R12                         0x1000
#define REG_R13                         0x2000
#define REG_R14                         0x4000
#define REG_R15                         0x8000

//=============================================================================
// Private Structures
//=============================================================================

//
// Scanned module tracking
//
typedef struct _ROP_SCANNED_MODULE {
    LIST_ENTRY ListEntry;
    PVOID ModuleBase;
    SIZE_T ModuleSize;
    UNICODE_STRING ModuleName;
    ULONG GadgetCount;
    LARGE_INTEGER ScanTime;
    ULONG ModuleHash;
} ROP_SCANNED_MODULE, *PROP_SCANNED_MODULE;

//
// Detection callback registration
//
typedef struct _ROP_CALLBACK_ENTRY {
    LIST_ENTRY ListEntry;
    ROP_DETECTION_CALLBACK Callback;
    PVOID Context;
    volatile LONG Active;
    EX_RUNDOWN_REF RundownRef;
} ROP_CALLBACK_ENTRY, *PROP_CALLBACK_ENTRY;

//
// Internal detector state (extends public structure)
//
typedef struct _ROP_DETECTOR_INTERNAL {
    //
    // Public detector structure (must be first)
    //
    ROP_DETECTOR Public;

    //
    // Callback management
    //
    LIST_ENTRY CallbackList;
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    //
    // Lookaside list for gadgets only (chain entries and results use pool)
    //
    SHADOWSTRIKE_LOOKASIDE GadgetLookaside;

    //
    // Rate limiting
    //
    volatile LONG64 AnalysisCount;
    volatile LONG64 LastResetTime;
    ULONG MaxAnalysesPerSecond;

    //
    // Dangerous gadget patterns (privileged operations)
    //
    struct {
        UCHAR Pattern[16];
        ULONG PatternSize;
        ULONG DangerScore;
        PCSTR Description;
    } DangerousPatterns[32];
    ULONG DangerousPatternCount;

} ROP_DETECTOR_INTERNAL, *PROP_DETECTOR_INTERNAL;

//
// Stack analysis context
//
typedef struct _ROP_ANALYSIS_CONTEXT {
    PROP_DETECTOR_INTERNAL Detector;
    HANDLE ProcessId;
    HANDLE ThreadId;

    //
    // Stack information
    //
    PVOID StackBase;
    PVOID StackLimit;
    PVOID CurrentSp;
    PULONG_PTR StackBuffer;
    SIZE_T StackBufferSize;

    //
    // Module cache for lookups
    //
    struct {
        PVOID Base;
        SIZE_T Size;
        BOOLEAN IsExecutable;
        WCHAR Name[64];
    } ModuleCache[64];
    ULONG ModuleCacheCount;

    //
    // Detection state
    //
    ULONG ConsecutiveGadgets;
    ULONG TotalGadgets;
    ULONG UnknownAddresses;
    ULONG NonExecutableAddresses;
    ROP_ATTACK_TYPE DetectedType;

    //
    // Timing
    //
    LARGE_INTEGER StartTime;
    ULONG TimeoutMs;

} ROP_ANALYSIS_CONTEXT, *PROP_ANALYSIS_CONTEXT;

//=============================================================================
// Internal Helpers
//=============================================================================

//
// Validates detector signature. Returns internal pointer or NULL on failure.
//
static
FORCEINLINE
PROP_DETECTOR_INTERNAL
RoppValidateDetector(
    _In_opt_ PROP_DETECTOR Detector
    )
{
    PROP_DETECTOR_INTERNAL internal;

    if (Detector == NULL) {
        return NULL;
    }

    if (Detector->Signature != ROP_DETECTOR_SIGNATURE) {
        return NULL;
    }

    if (InterlockedCompareExchange(&Detector->Initialized, 1, 1) != 1) {
        return NULL;
    }

    internal = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);
    return internal;
}

//
// Acquires rundown protection. Must be released with ExReleaseRundownProtection.
//
static
FORCEINLINE
BOOLEAN
RoppAcquireRundown(
    _In_ PROP_DETECTOR Detector
    )
{
    return ExAcquireRundownProtection(&Detector->RundownRef);
}

static
FORCEINLINE
VOID
RoppReleaseRundown(
    _In_ PROP_DETECTOR Detector
    )
{
    ExReleaseRundownProtection(&Detector->RundownRef);
}

//=============================================================================
// Forward Declarations
//=============================================================================

static
ULONG
RoppHashAddress(
    _In_ PVOID Address
    );

static
NTSTATUS
RoppAllocateGadget(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _Out_ PROP_GADGET* Gadget
    );

static
VOID
RoppFreeGadget(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _In_ PROP_GADGET Gadget
    );

static
NTSTATUS
RoppAllocateChainEntry(
    _Out_ PROP_CHAIN_ENTRY* Entry
    );

static
VOID
RoppFreeChainEntry(
    _In_ PROP_CHAIN_ENTRY Entry
    );

static
NTSTATUS
RoppAllocateResult(
    _Out_ PROP_DETECTION_RESULT* Result
    );

static
ROP_GADGET_TYPE
RoppClassifyGadget(
    _In_reads_bytes_(Size) PUCHAR Bytes,
    _In_ ULONG Size,
    _Out_ PULONG GadgetSize
    );

static
ULONG
RoppDecodeModRMLength(
    _In_reads_bytes_(MaxSize) PUCHAR Bytes,
    _In_ ULONG MaxSize
    );

static
VOID
RoppAnalyzeGadgetSemantics(
    _Inout_ PROP_GADGET Gadget
    );

static
ULONG
RoppCalculateDangerScore(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _In_ PROP_GADGET Gadget
    );

static
NTSTATUS
RoppInitializeAnalysisContext(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_opt_ PCONTEXT ThreadContext,
    _Out_ PROP_ANALYSIS_CONTEXT Context
    );

static
VOID
RoppCleanupAnalysisContext(
    _Inout_ PROP_ANALYSIS_CONTEXT Context
    );

static
NTSTATUS
RoppCaptureStack(
    _Inout_ PROP_ANALYSIS_CONTEXT Context
    );

static
BOOLEAN
RoppIsExecutableAddress(
    _In_ PROP_ANALYSIS_CONTEXT Context,
    _In_ PVOID Address
    );

static
NTSTATUS
RoppBuildModuleCache(
    _Inout_ PROP_ANALYSIS_CONTEXT Context
    );

static
NTSTATUS
RoppDetectChain(
    _Inout_ PROP_ANALYSIS_CONTEXT Context,
    _Inout_ PROP_DETECTION_RESULT Result
    );

static
BOOLEAN
RoppDetectStackPivot(
    _In_ PROP_ANALYSIS_CONTEXT Context,
    _Out_ PPVOID PivotSource,
    _Out_ PPVOID PivotDestination
    );

static
ROP_ATTACK_TYPE
RoppClassifyAttack(
    _In_ PROP_DETECTION_RESULT Result
    );

static
VOID
RoppCalculateConfidence(
    _Inout_ PROP_DETECTION_RESULT Result
    );

static
VOID
RoppInferPayload(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _Inout_ PROP_DETECTION_RESULT Result
    );

static
VOID
RoppNotifyCallbacks(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _In_ PROP_DETECTION_RESULT Result
    );

static
BOOLEAN
RoppCheckRateLimit(
    _In_ PROP_DETECTOR_INTERNAL Detector
    );

static
VOID
RoppInitializeDangerousPatterns(
    _Inout_ PROP_DETECTOR_INTERNAL Detector
    );

static
BOOLEAN
RoppIsModuleAlreadyScanned(
    _In_ PROP_DETECTOR Detector,
    _In_ PVOID ModuleBase
    );

static
BOOLEAN
RoppValidatePeHeaders(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _Out_ PIMAGE_NT_HEADERS* NtHeaders
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

_Use_decl_annotations_
NTSTATUS
RopInitialize(
    PROP_DETECTOR* Detector
    )
/*++

Routine Description:

    Initializes the ROP/JOP detection engine.

Arguments:

    Detector - Receives pointer to initialized detector

Return Value:

    STATUS_SUCCESS on success
    STATUS_INSUFFICIENT_RESOURCES on allocation failure
    STATUS_INVALID_PARAMETER if Detector is NULL

--*/
{
    NTSTATUS status;
    PROP_DETECTOR_INTERNAL internalDetector = NULL;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate internal detector structure
    //
    internalDetector = (PROP_DETECTOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ROP_DETECTOR_INTERNAL),
        ROP_POOL_TAG_CONTEXT
        );

    if (internalDetector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internalDetector, sizeof(ROP_DETECTOR_INTERNAL));

    //
    // Set signature for validation
    //
    internalDetector->Public.Signature = ROP_DETECTOR_SIGNATURE;

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&internalDetector->Public.RundownRef);

    //
    // Initialize gadget hash table
    //
    for (i = 0; i < ROP_GADGET_HASH_BUCKETS; i++) {
        InitializeListHead(&internalDetector->Public.GadgetHash[i]);
    }
    InitializeListHead(&internalDetector->Public.GadgetList);
    ExInitializePushLock(&internalDetector->Public.GadgetLock);

    //
    // Initialize module tracking
    //
    InitializeListHead(&internalDetector->Public.ScannedModules);
    ExInitializePushLock(&internalDetector->Public.ModuleLock);

    //
    // Initialize callback management
    //
    InitializeListHead(&internalDetector->CallbackList);
    ExInitializePushLock(&internalDetector->CallbackLock);

    //
    // Initialize gadget lookaside list only.
    // Chain entries and results use direct pool allocation to avoid
    // allocator/deallocator mismatch issues.
    //
    status = ShadowStrikeLookasideInit(
        &internalDetector->GadgetLookaside,
        sizeof(ROP_GADGET),
        ROP_POOL_TAG_GADGET,
        ROP_GADGET_LOOKASIDE_DEPTH,
        FALSE   // Non-paged
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Set default configuration
    //
    internalDetector->Public.Config.MinChainLength = ROP_MIN_CHAIN_LENGTH;
    internalDetector->Public.Config.MaxChainLength = ROP_MAX_CHAIN_LENGTH;
    internalDetector->Public.Config.ConfidenceThreshold = 50;
    internalDetector->Public.Config.ScanSystemModules = TRUE;
    internalDetector->Public.Config.EnableSemanticAnalysis = TRUE;

    //
    // Initialize rate limiting
    //
    internalDetector->MaxAnalysesPerSecond = 1000;
    KeQuerySystemTime((PLARGE_INTEGER)&internalDetector->LastResetTime);

    //
    // Initialize dangerous gadget patterns
    //
    RoppInitializeDangerousPatterns(internalDetector);

    //
    // Record start time for statistics
    //
    KeQuerySystemTime(&internalDetector->Public.Stats.StartTime);

    //
    // Mark as initialized (interlocked store)
    //
    InterlockedExchange(&internalDetector->Public.Initialized, 1);

    *Detector = &internalDetector->Public;
    return STATUS_SUCCESS;

Cleanup:
    if (internalDetector != NULL) {
        if (internalDetector->GadgetLookaside.Initialized) {
            ShadowStrikeLookasideCleanup(&internalDetector->GadgetLookaside);
        }

        ShadowStrikeFreePoolWithTag(internalDetector, ROP_POOL_TAG_CONTEXT);
    }

    return status;
}


_Use_decl_annotations_
VOID
RopShutdown(
    PROP_DETECTOR Detector
    )
/*++

Routine Description:

    Shuts down the ROP detector and releases all resources.
    Uses rundown protection to wait for all in-flight operations.

Arguments:

    Detector - Detector to shut down

--*/
{
    PROP_DETECTOR_INTERNAL internalDetector;
    PLIST_ENTRY entry;
    PROP_GADGET gadget;
    PROP_SCANNED_MODULE module;
    PROP_CALLBACK_ENTRY callback;

    PAGED_CODE();

    if (Detector == NULL || Detector->Signature != ROP_DETECTOR_SIGNATURE) {
        return;
    }

    //
    // Atomically mark as not initialized. If it was already 0, bail.
    //
    if (InterlockedExchange(&Detector->Initialized, 0) == 0) {
        return;
    }

    //
    // Wait for all in-flight operations to complete.
    // After this returns, no new rundown acquisitions will succeed.
    //
    ExWaitForRundownProtectionRelease(&Detector->RundownRef);

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    //
    // Free all gadgets
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->GadgetLock);

    while (!IsListEmpty(&Detector->GadgetList)) {
        entry = RemoveHeadList(&Detector->GadgetList);
        gadget = CONTAINING_RECORD(entry, ROP_GADGET, ListEntry);
        RoppFreeGadget(internalDetector, gadget);
    }

    ExReleasePushLockExclusive(&Detector->GadgetLock);
    KeLeaveCriticalRegion();

    //
    // Free scanned modules list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ModuleLock);

    while (!IsListEmpty(&Detector->ScannedModules)) {
        entry = RemoveHeadList(&Detector->ScannedModules);
        module = CONTAINING_RECORD(entry, ROP_SCANNED_MODULE, ListEntry);

        if (module->ModuleName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(module->ModuleName.Buffer, ROP_POOL_TAG_CONTEXT);
        }
        ShadowStrikeFreePoolWithTag(module, ROP_POOL_TAG_CONTEXT);
    }

    ExReleasePushLockExclusive(&Detector->ModuleLock);
    KeLeaveCriticalRegion();

    //
    // Free callbacks
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internalDetector->CallbackLock);

    while (!IsListEmpty(&internalDetector->CallbackList)) {
        entry = RemoveHeadList(&internalDetector->CallbackList);
        callback = CONTAINING_RECORD(entry, ROP_CALLBACK_ENTRY, ListEntry);
        ShadowStrikeFreePoolWithTag(callback, ROP_POOL_TAG_CONTEXT);
    }

    ExReleasePushLockExclusive(&internalDetector->CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Cleanup lookaside list
    //
    ShadowStrikeLookasideCleanup(&internalDetector->GadgetLookaside);

    //
    // Invalidate signature before freeing
    //
    Detector->Signature = 0;

    //
    // Free detector structure
    //
    ShadowStrikeFreePoolWithTag(internalDetector, ROP_POOL_TAG_CONTEXT);
}

//=============================================================================
// Public API - Gadget Database
//=============================================================================

_Use_decl_annotations_
NTSTATUS
RopScanModuleForGadgets(
    PROP_DETECTOR Detector,
    PVOID ModuleBase,
    SIZE_T ModuleSize,
    PUNICODE_STRING ModuleName
    )
/*++

Routine Description:

    Scans a loaded module for ROP/JOP gadgets and adds them to the
    gadget database. Validates PE structure and checks for duplicates.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_SCANNED_MODULE moduleEntry = NULL;
    PUCHAR currentByte;
    PUCHAR sectionEnd;
    ULONG gadgetCount = 0;
    ULONG offset;
    ROP_GADGET_TYPE gadgetType;
    ULONG gadgetSize;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG sectionIndex;
    BOOLEAN isExecutable;
    ULONG sectionVa;
    ULONG sectionSize;

    PAGED_CODE();

    internalDetector = RoppValidateDetector(Detector);
    if (internalDetector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ModuleBase == NULL || ModuleSize == 0 || ModuleSize > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RoppAcquireRundown(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Check for duplicate module scan
    //
    if (RoppIsModuleAlreadyScanned(Detector, ModuleBase)) {
        RoppReleaseRundown(Detector);
        return STATUS_OBJECTID_EXISTS;
    }

    //
    // Validate PE structure with bounds checking
    //
    if (!RoppValidatePeHeaders(ModuleBase, ModuleSize, &ntHeaders)) {
        RoppReleaseRundown(Detector);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // Allocate module tracking entry
    //
    moduleEntry = (PROP_SCANNED_MODULE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ROP_SCANNED_MODULE),
        ROP_POOL_TAG_CONTEXT
        );

    if (moduleEntry == NULL) {
        RoppReleaseRundown(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(moduleEntry, sizeof(ROP_SCANNED_MODULE));
    moduleEntry->ModuleBase = ModuleBase;
    moduleEntry->ModuleSize = ModuleSize;

    //
    // Clone module name
    //
    if (ModuleName != NULL && ModuleName->Length > 0 && ModuleName->Buffer != NULL) {
        moduleEntry->ModuleName.Length = ModuleName->Length;
        moduleEntry->ModuleName.MaximumLength = ModuleName->Length + sizeof(WCHAR);
        moduleEntry->ModuleName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            moduleEntry->ModuleName.MaximumLength,
            ROP_POOL_TAG_CONTEXT
            );

        if (moduleEntry->ModuleName.Buffer != NULL) {
            RtlCopyMemory(
                moduleEntry->ModuleName.Buffer,
                ModuleName->Buffer,
                ModuleName->Length
                );
            moduleEntry->ModuleName.Buffer[ModuleName->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    //
    // Scan each executable section for gadgets
    //
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (sectionIndex = 0; sectionIndex < ntHeaders->FileHeader.NumberOfSections; sectionIndex++) {

        isExecutable = (sectionHeader[sectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        if (!isExecutable) {
            continue;
        }

        sectionVa = sectionHeader[sectionIndex].VirtualAddress;
        sectionSize = sectionHeader[sectionIndex].Misc.VirtualSize;

        //
        // Bounds-check section against module size
        //
        if (sectionVa >= ModuleSize ||
            sectionSize == 0 ||
            sectionVa + sectionSize > ModuleSize ||
            sectionVa + sectionSize < sectionVa) {
            continue;
        }

        __try {
            currentByte = (PUCHAR)ModuleBase + sectionVa;
            sectionEnd = currentByte + sectionSize;

            for (offset = 0; offset < sectionSize; offset++) {

                gadgetType = RoppClassifyGadget(
                    currentByte + offset,
                    sectionSize - offset,
                    &gadgetSize
                    );

                if (gadgetType != GadgetType_Unknown && gadgetSize > 0) {
                    ULONG backScan;
                    ULONG maxBackScan = min(ROP_GADGET_MAX_SIZE, offset);

                    for (backScan = 0; backScan <= maxBackScan; backScan++) {
                        PVOID gadgetAddr = currentByte + offset - backScan;
                        ULONG totalSize = backScan + gadgetSize;

                        if (totalSize >= 2 && totalSize <= ROP_GADGET_MAX_SIZE) {
                            status = RopAddGadget(
                                Detector,
                                gadgetAddr,
                                ModuleBase,
                                (PUCHAR)gadgetAddr,
                                totalSize,
                                gadgetType
                                );

                            if (NT_SUCCESS(status)) {
                                gadgetCount++;
                                if (gadgetCount >= ROP_MAX_GADGETS_PER_MODULE) {
                                    goto ScanComplete;
                                }
                            }
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
    }

ScanComplete:
    //
    // Update module entry and add to tracked list
    //
    moduleEntry->GadgetCount = gadgetCount;
    KeQuerySystemTime(&moduleEntry->ScanTime);
    moduleEntry->ModuleHash = RoppHashAddress(ModuleBase);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ModuleLock);
    InsertTailList(&Detector->ScannedModules, &moduleEntry->ListEntry);
    ExReleasePushLockExclusive(&Detector->ModuleLock);
    KeLeaveCriticalRegion();

    InterlockedAdd64(&Detector->Stats.GadgetsIndexed, gadgetCount);

    RoppReleaseRundown(Detector);
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
RopAddGadget(
    PROP_DETECTOR Detector,
    PVOID Address,
    PVOID ModuleBase,
    PUCHAR Bytes,
    ULONG Size,
    ROP_GADGET_TYPE Type
    )
/*++

Routine Description:

    Adds a gadget to the detection database.

--*/
{
    NTSTATUS status;
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_GADGET gadget = NULL;
    ULONG hashBucket;

    PAGED_CODE();

    internalDetector = RoppValidateDetector(Detector);
    if (internalDetector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Address == NULL || Bytes == NULL || Size == 0 || Size > ROP_GADGET_MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate gadget from lookaside
    //
    status = RoppAllocateGadget(internalDetector, &gadget);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Initialize gadget
    //
    gadget->Address = Address;
    gadget->ModuleBase = ModuleBase;
    gadget->ModuleOffset = (ULONG)((ULONG_PTR)Address - (ULONG_PTR)ModuleBase);
    gadget->Type = Type;
    gadget->Size = Size;

    RtlCopyMemory(gadget->Bytes, Bytes, Size);

    if (Detector->Config.EnableSemanticAnalysis) {
        RoppAnalyzeGadgetSemantics(gadget);
    }

    gadget->DangerScore = RoppCalculateDangerScore(internalDetector, gadget);

    //
    // Add to hash table and global list under exclusive lock
    //
    hashBucket = RoppHashAddress(Address) % ROP_GADGET_HASH_BUCKETS;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->GadgetLock);

    InsertTailList(&Detector->GadgetList, &gadget->ListEntry);
    InsertTailList(&Detector->GadgetHash[hashBucket], &gadget->HashEntry);
    InterlockedIncrement(&Detector->GadgetCount);

    ExReleasePushLockExclusive(&Detector->GadgetLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
RopLookupGadget(
    PROP_DETECTOR Detector,
    PVOID Address,
    PROP_GADGET GadgetCopy
    )
/*++

Routine Description:

    Looks up a gadget by address. Copies the gadget data out to avoid
    lifetime issues (the caller does not hold a reference to the internal
    gadget after this call returns).

Arguments:

    Detector - Initialized detector
    Address - Gadget address to find
    GadgetCopy - Receives a COPY of the gadget data if found

Return Value:

    STATUS_SUCCESS if found
    STATUS_NOT_FOUND if not in database

--*/
{
    ULONG hashBucket;
    PLIST_ENTRY entry;
    PROP_GADGET current;
    NTSTATUS status = STATUS_NOT_FOUND;

    PAGED_CODE();

    if (Detector == NULL || Detector->Signature != ROP_DETECTOR_SIGNATURE ||
        Address == NULL || GadgetCopy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(GadgetCopy, sizeof(ROP_GADGET));

    hashBucket = RoppHashAddress(Address) % ROP_GADGET_HASH_BUCKETS;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->GadgetLock);

    for (entry = Detector->GadgetHash[hashBucket].Flink;
         entry != &Detector->GadgetHash[hashBucket];
         entry = entry->Flink) {

        current = CONTAINING_RECORD(entry, ROP_GADGET, HashEntry);

        if (current->Address == Address) {
            //
            // Copy gadget data out. The list linkage fields in the copy
            // are meaningless but harmless.
            //
            RtlCopyMemory(GadgetCopy, current, sizeof(ROP_GADGET));
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockShared(&Detector->GadgetLock);
    KeLeaveCriticalRegion();

    return status;
}

//=============================================================================
// Public API - Detection
//=============================================================================

_Use_decl_annotations_
NTSTATUS
RopAnalyzeStack(
    PROP_DETECTOR Detector,
    HANDLE ProcessId,
    HANDLE ThreadId,
    PCONTEXT ThreadContext,
    PROP_DETECTION_RESULT* Result
    )
/*++

Routine Description:

    Analyzes a thread's stack for ROP/JOP chains.

--*/
{
    NTSTATUS status;
    PROP_DETECTOR_INTERNAL internalDetector;
    ROP_ANALYSIS_CONTEXT context;
    PROP_DETECTION_RESULT result = NULL;

    PAGED_CODE();

    internalDetector = RoppValidateDetector(Detector);
    if (internalDetector == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    if (!RoppAcquireRundown(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Check rate limit
    //
    if (!RoppCheckRateLimit(internalDetector)) {
        RoppReleaseRundown(Detector);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Initialize analysis context
    //
    status = RoppInitializeAnalysisContext(
        internalDetector,
        ProcessId,
        ThreadId,
        ThreadContext,
        &context
        );

    if (!NT_SUCCESS(status)) {
        RoppReleaseRundown(Detector);
        return status;
    }

    //
    // Allocate result structure (pool, not lookaside)
    //
    status = RoppAllocateResult(&result);
    if (!NT_SUCCESS(status)) {
        RoppCleanupAnalysisContext(&context);
        RoppReleaseRundown(Detector);
        return status;
    }

    result->ProcessId = ProcessId;
    result->ThreadId = ThreadId;
    result->StackBase = context.StackBase;
    result->StackLimit = context.StackLimit;
    result->CurrentSp = context.CurrentSp;
    InitializeListHead(&result->ChainEntries);

    //
    // Capture stack contents
    //
    status = RoppCaptureStack(&context);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Build module cache for fast lookups
    //
    status = RoppBuildModuleCache(&context);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Detect stack pivot
    //
    result->StackPivotDetected = RoppDetectStackPivot(
        &context,
        &result->PivotSource,
        &result->PivotDestination
        );

    //
    // Analyze stack for gadget chains
    //
    status = RoppDetectChain(&context, result);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Classify the attack type
    //
    result->AttackType = RoppClassifyAttack(result);

    //
    // Calculate confidence and severity scores
    //
    RoppCalculateConfidence(result);

    //
    // Infer payload behavior if chain detected
    //
    if (result->ChainDetected) {
        RoppInferPayload(internalDetector, result);
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.StacksAnalyzed);
    if (result->ChainDetected) {
        InterlockedIncrement64(&Detector->Stats.ChainsDetected);
    }

    //
    // Notify callbacks if chain detected and confidence meets threshold
    //
    if (result->ChainDetected && result->ConfidenceScore >= Detector->Config.ConfidenceThreshold) {
        RoppNotifyCallbacks(internalDetector, result);
    }

    //
    // Transfer ownership to caller
    //
    *Result = result;
    result = NULL;

    RoppCleanupAnalysisContext(&context);
    RoppReleaseRundown(Detector);

    return (*Result)->ChainDetected ? STATUS_SUCCESS : STATUS_NOT_FOUND;

Cleanup:
    RoppCleanupAnalysisContext(&context);

    if (result != NULL) {
        RopFreeResult(result);
    }

    RoppReleaseRundown(Detector);
    return status;
}


_Use_decl_annotations_
NTSTATUS
RopAnalyzeStackBuffer(
    PROP_DETECTOR Detector,
    PVOID StackBuffer,
    SIZE_T Size,
    PVOID StackBase,
    PROP_DETECTION_RESULT* Result
    )
/*++

Routine Description:

    Analyzes a pre-captured stack buffer for ROP/JOP chains.

--*/
{
    NTSTATUS status;
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_DETECTION_RESULT result = NULL;
    PULONG_PTR stackPtr;
    SIZE_T slotCount;
    SIZE_T i;
    ULONG consecutiveGadgets = 0;
    ULONG totalGadgets = 0;
    ROP_GADGET gadgetCopy;
    PROP_CHAIN_ENTRY chainEntry;

    PAGED_CODE();

    internalDetector = RoppValidateDetector(Detector);
    if (internalDetector == NULL ||
        StackBuffer == NULL || Size == 0 || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    if (!ShadowStrikeIsAligned(StackBuffer, ROP_STACK_ALIGNMENT)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    if (Size > ROP_STACK_SAMPLE_SIZE || Size < sizeof(ULONG_PTR)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RoppAcquireRundown(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Allocate result (pool, not lookaside)
    //
    status = RoppAllocateResult(&result);
    if (!NT_SUCCESS(status)) {
        RoppReleaseRundown(Detector);
        return status;
    }

    InitializeListHead(&result->ChainEntries);
    result->StackBase = StackBase;

    stackPtr = (PULONG_PTR)StackBuffer;
    slotCount = Size / sizeof(ULONG_PTR);

    //
    // Scan stack slots for gadget addresses
    //
    for (i = 0; i < slotCount; i++) {
        ULONG_PTR value = stackPtr[i];

        if (value < 0x10000) {
            consecutiveGadgets = 0;
            continue;
        }

        //
        // Look up in gadget database (copy-out)
        //
        status = RopLookupGadget(Detector, (PVOID)value, &gadgetCopy);

        if (NT_SUCCESS(status)) {
            totalGadgets++;
            consecutiveGadgets++;

            //
            // Allocate chain entry (pool, not lookaside)
            //
            status = RoppAllocateChainEntry(&chainEntry);
            if (NT_SUCCESS(status)) {
                chainEntry->GadgetAddress = (PVOID)value;
                chainEntry->GadgetType = gadgetCopy.Type;
                chainEntry->GadgetSize = gadgetCopy.Size;
                chainEntry->GadgetDangerScore = gadgetCopy.DangerScore;
                chainEntry->GadgetIsPrivileged = gadgetCopy.IsPrivileged;
                chainEntry->GadgetRegistersModified = gadgetCopy.Semantics.RegistersModified;
                chainEntry->StackOffset = i * sizeof(ULONG_PTR);
                chainEntry->StackValue = value;
                chainEntry->Index = result->ChainLength;

                InsertTailList(&result->ChainEntries, &chainEntry->ListEntry);
                result->ChainLength++;
            }

            if (consecutiveGadgets >= Detector->Config.MinChainLength) {
                result->ChainDetected = TRUE;
            }
        } else {
            if (consecutiveGadgets > 0 && consecutiveGadgets < Detector->Config.MinChainLength) {
                consecutiveGadgets = 0;
            }
        }
    }

    result->UniqueGadgets = totalGadgets;

    if (result->ChainDetected) {
        result->AttackType = RoppClassifyAttack(result);
        RoppCalculateConfidence(result);
        RoppInferPayload(internalDetector, result);

        *Result = result;
        RoppReleaseRundown(Detector);
        return STATUS_SUCCESS;
    }

    RopFreeResult(result);
    RoppReleaseRundown(Detector);
    return STATUS_NOT_FOUND;
}


_Use_decl_annotations_
NTSTATUS
RopValidateCallStack(
    PROP_DETECTOR Detector,
    HANDLE ProcessId,
    HANDLE ThreadId,
    PBOOLEAN IsValid,
    PULONG SuspicionScore
    )
/*++

Routine Description:

    Validates a thread's call stack for integrity.

--*/
{
    NTSTATUS status;
    PROP_DETECTION_RESULT result = NULL;
    ULONG score = 0;

    PAGED_CODE();

    if (RoppValidateDetector(Detector) == NULL || IsValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsValid = TRUE;
    if (SuspicionScore != NULL) {
        *SuspicionScore = 0;
    }

    status = RopAnalyzeStack(Detector, ProcessId, ThreadId, NULL, &result);

    if (status == STATUS_NOT_FOUND) {
        *IsValid = TRUE;
        if (result != NULL) {
            //
            // Even when no chain is detected, check pivot
            //
            if (result->StackPivotDetected) {
                *IsValid = FALSE;
                score = 70;
            }
            RopFreeResult(result);
        }
        if (SuspicionScore != NULL) {
            *SuspicionScore = score;
        }
        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (result->ChainDetected) {
        *IsValid = FALSE;
        score = result->ConfidenceScore;
    } else if (result->StackPivotDetected) {
        *IsValid = FALSE;
        score = 70;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = score;
    }

    RopFreeResult(result);

    return STATUS_SUCCESS;
}

//=============================================================================
// Public API - Results
//=============================================================================

_Use_decl_annotations_
VOID
RopFreeResult(
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Frees a detection result and all chain entries.
    All allocations are from pool (not lookaside), so we use
    ShadowStrikeFreePoolWithTag consistently.

--*/
{
    PLIST_ENTRY entry;
    PROP_CHAIN_ENTRY chainEntry;

    PAGED_CODE();

    if (Result == NULL) {
        return;
    }

    //
    // Free chain entries (all allocated from pool via RoppAllocateChainEntry)
    //
    while (!IsListEmpty(&Result->ChainEntries)) {
        entry = RemoveHeadList(&Result->ChainEntries);
        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);
        RoppFreeChainEntry(chainEntry);
    }

    //
    // Free result (allocated from pool via RoppAllocateResult)
    //
    ShadowStrikeFreePoolWithTag(Result, ROP_POOL_TAG_CONTEXT);
}

//=============================================================================
// Public API - Callbacks
//=============================================================================

_Use_decl_annotations_
NTSTATUS
RopRegisterCallback(
    PROP_DETECTOR Detector,
    ROP_DETECTION_CALLBACK Callback,
    PVOID Context
    )
/*++

Routine Description:

    Registers a callback for ROP chain detection notifications.
    Each callback gets its own rundown ref for safe unregistration.

--*/
{
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_CALLBACK_ENTRY callbackEntry;

    PAGED_CODE();

    internalDetector = RoppValidateDetector(Detector);
    if (internalDetector == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RoppAcquireRundown(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    if (internalDetector->CallbackCount >= ROP_MAX_CALLBACKS) {
        RoppReleaseRundown(Detector);
        return STATUS_QUOTA_EXCEEDED;
    }

    callbackEntry = (PROP_CALLBACK_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ROP_CALLBACK_ENTRY),
        ROP_POOL_TAG_CONTEXT
        );

    if (callbackEntry == NULL) {
        RoppReleaseRundown(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(callbackEntry, sizeof(ROP_CALLBACK_ENTRY));
    callbackEntry->Callback = Callback;
    callbackEntry->Context = Context;
    InterlockedExchange(&callbackEntry->Active, TRUE);
    ExInitializeRundownProtection(&callbackEntry->RundownRef);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internalDetector->CallbackLock);

    InsertTailList(&internalDetector->CallbackList, &callbackEntry->ListEntry);
    InterlockedIncrement(&internalDetector->CallbackCount);

    ExReleasePushLockExclusive(&internalDetector->CallbackLock);
    KeLeaveCriticalRegion();

    RoppReleaseRundown(Detector);
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
RopUnregisterCallback(
    PROP_DETECTOR Detector,
    ROP_DETECTION_CALLBACK Callback
    )
/*++

Routine Description:

    Unregisters a previously registered callback.
    Uses per-callback rundown protection to ensure no in-flight
    invocations exist before freeing the entry.

--*/
{
    PROP_DETECTOR_INTERNAL internalDetector;
    PLIST_ENTRY entry;
    PROP_CALLBACK_ENTRY callbackEntry;
    PROP_CALLBACK_ENTRY foundEntry = NULL;

    PAGED_CODE();

    internalDetector = RoppValidateDetector(Detector);
    if (internalDetector == NULL || Callback == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internalDetector->CallbackLock);

    for (entry = internalDetector->CallbackList.Flink;
         entry != &internalDetector->CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, ROP_CALLBACK_ENTRY, ListEntry);

        if (callbackEntry->Callback == Callback) {
            //
            // Mark inactive so no new invocations start
            //
            InterlockedExchange(&callbackEntry->Active, FALSE);
            RemoveEntryList(&callbackEntry->ListEntry);
            InterlockedDecrement(&internalDetector->CallbackCount);
            foundEntry = callbackEntry;
            break;
        }
    }

    ExReleasePushLockExclusive(&internalDetector->CallbackLock);
    KeLeaveCriticalRegion();

    if (foundEntry != NULL) {
        //
        // Wait for any in-flight callback invocations to complete
        //
        ExWaitForRundownProtectionRelease(&foundEntry->RundownRef);
        ShadowStrikeFreePoolWithTag(foundEntry, ROP_POOL_TAG_CONTEXT);
    }
}

//=============================================================================
// Public API - Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
RopGetStatistics(
    PROP_DETECTOR Detector,
    PROP_STATISTICS Stats
    )
/*++

Routine Description:

    Retrieves detector statistics.

--*/
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry;
    ULONG moduleCount = 0;

    PAGED_CODE();

    if (RoppValidateDetector(Detector) == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RoppAcquireRundown(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    Stats->GadgetCount = (ULONG)Detector->GadgetCount;
    Stats->StacksAnalyzed = Detector->Stats.StacksAnalyzed;
    Stats->ChainsDetected = Detector->Stats.ChainsDetected;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ModuleLock);

    for (entry = Detector->ScannedModules.Flink;
         entry != &Detector->ScannedModules;
         entry = entry->Flink) {
        moduleCount++;
    }

    ExReleasePushLockShared(&Detector->ModuleLock);
    KeLeaveCriticalRegion();

    Stats->ModulesScanned = moduleCount;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    RoppReleaseRundown(Detector);
    return STATUS_SUCCESS;
}

//=============================================================================
// Private Functions - Allocation
//=============================================================================

static
ULONG
RoppHashAddress(
    PVOID Address
    )
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG hash = 2166136261;

    while (addr != 0) {
        hash ^= (ULONG)(addr & 0xFF);
        hash *= 16777619;
        addr >>= 8;
    }

    return hash;
}


static
NTSTATUS
RoppAllocateGadget(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_GADGET* Gadget
    )
{
    PROP_GADGET gadget;

    gadget = (PROP_GADGET)ShadowStrikeLookasideAllocate(&Detector->GadgetLookaside);

    if (gadget == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(gadget, sizeof(ROP_GADGET));
    *Gadget = gadget;

    return STATUS_SUCCESS;
}


static
VOID
RoppFreeGadget(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_GADGET Gadget
    )
{
    if (Gadget != NULL) {
        ShadowStrikeLookasideFree(&Detector->GadgetLookaside, Gadget);
    }
}


//
// Chain entries and results are ALWAYS allocated from pool (never lookaside)
// so that RopFreeResult can safely use ShadowStrikeFreePoolWithTag.
//
static
NTSTATUS
RoppAllocateChainEntry(
    PROP_CHAIN_ENTRY* Entry
    )
{
    PROP_CHAIN_ENTRY entry;

    entry = (PROP_CHAIN_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ROP_CHAIN_ENTRY),
        ROP_POOL_TAG_CHAIN
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(ROP_CHAIN_ENTRY));
    *Entry = entry;

    return STATUS_SUCCESS;
}


static
VOID
RoppFreeChainEntry(
    PROP_CHAIN_ENTRY Entry
    )
{
    if (Entry != NULL) {
        ShadowStrikeFreePoolWithTag(Entry, ROP_POOL_TAG_CHAIN);
    }
}


static
NTSTATUS
RoppAllocateResult(
    PROP_DETECTION_RESULT* Result
    )
{
    PROP_DETECTION_RESULT result;

    result = (PROP_DETECTION_RESULT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ROP_DETECTION_RESULT),
        ROP_POOL_TAG_CONTEXT
        );

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(ROP_DETECTION_RESULT));
    *Result = result;

    return STATUS_SUCCESS;
}


//=============================================================================
// Private Functions - PE Validation
//=============================================================================

static
BOOLEAN
RoppValidatePeHeaders(
    PVOID ModuleBase,
    SIZE_T ModuleSize,
    PIMAGE_NT_HEADERS* NtHeaders
    )
/*++

Routine Description:

    Validates PE headers with full bounds checking against ModuleSize.

--*/
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    ULONG e_lfanew;
    SIZE_T ntHeaderEnd;
    SIZE_T sectionTableEnd;

    *NtHeaders = NULL;

    if (ModuleSize < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        e_lfanew = (ULONG)dosHeader->e_lfanew;

        //
        // Bounds check e_lfanew
        //
        if (e_lfanew >= ModuleSize) {
            return FALSE;
        }

        ntHeaderEnd = (SIZE_T)e_lfanew + sizeof(IMAGE_NT_HEADERS);
        if (ntHeaderEnd > ModuleSize || ntHeaderEnd < (SIZE_T)e_lfanew) {
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }

        //
        // Validate NumberOfSections won't overflow the section table
        //
        if (ntHeaders->FileHeader.NumberOfSections > 96) {
            return FALSE;
        }

        sectionTableEnd = (SIZE_T)e_lfanew +
                          FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                          ntHeaders->FileHeader.SizeOfOptionalHeader +
                          ((SIZE_T)ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        if (sectionTableEnd > ModuleSize) {
            return FALSE;
        }

        *NtHeaders = ntHeaders;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}


static
BOOLEAN
RoppIsModuleAlreadyScanned(
    PROP_DETECTOR Detector,
    PVOID ModuleBase
    )
/*++

Routine Description:

    Checks if a module has already been scanned (deduplication).

--*/
{
    PLIST_ENTRY entry;
    PROP_SCANNED_MODULE module;
    BOOLEAN found = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ModuleLock);

    for (entry = Detector->ScannedModules.Flink;
         entry != &Detector->ScannedModules;
         entry = entry->Flink) {

        module = CONTAINING_RECORD(entry, ROP_SCANNED_MODULE, ListEntry);
        if (module->ModuleBase == ModuleBase) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Detector->ModuleLock);
    KeLeaveCriticalRegion();

    return found;
}

//=============================================================================
// Private Functions - Gadget Analysis
//=============================================================================

static
ULONG
RoppDecodeModRMLength(
    PUCHAR Bytes,
    ULONG MaxSize
    )
/*++

Routine Description:

    Decodes the total length of a ModR/M-addressed instruction suffix
    (ModR/M byte + optional SIB + optional displacement).
    Returns the number of bytes consumed starting from the ModR/M byte.

--*/
{
    UCHAR modrm;
    UCHAR mod;
    UCHAR rm;
    ULONG length = 1;  // ModR/M byte itself

    if (MaxSize < 1) {
        return 0;
    }

    modrm = Bytes[0];
    mod = (modrm & MODRM_MOD_MASK) >> 6;
    rm = modrm & MODRM_RM_MASK;

    if (mod == 3) {
        //
        // Register direct — no SIB, no displacement
        //
        return 1;
    }

    //
    // Check for SIB byte (rm == 4 and mod != 3)
    //
    if (rm == 4) {
        length++;  // SIB byte
        if (length > MaxSize) return 0;
    }

    //
    // Displacement size
    //
    if (mod == 0) {
        if (rm == 5) {
            length += 4;  // disp32 (RIP-relative on x64)
        }
        // rm == 4 with SIB: check SIB base
        if (rm == 4 && length >= 2) {
            UCHAR sib = Bytes[1];
            if ((sib & 0x07) == 5) {
                length += 4;  // disp32
            }
        }
    } else if (mod == 1) {
        length += 1;  // disp8
    } else if (mod == 2) {
        length += 4;  // disp32
    }

    if (length > MaxSize) {
        return 0;
    }

    return length;
}


static
ROP_GADGET_TYPE
RoppClassifyGadget(
    PUCHAR Bytes,
    ULONG Size,
    PULONG GadgetSize
    )
/*++

Routine Description:

    Classifies a potential gadget based on its terminating instruction.
    Properly decodes ModR/M + SIB + displacement for FF-prefix instructions.

--*/
{
    UCHAR opcode;
    UCHAR modrm;
    UCHAR reg;
    UCHAR mod;
    ULONG modrmLen;

    if (Bytes == NULL || Size == 0 || GadgetSize == NULL) {
        return GadgetType_Unknown;
    }

    *GadgetSize = 0;
    opcode = Bytes[0];

    if (opcode == OPCODE_RET) {
        *GadgetSize = 1;
        return GadgetType_Ret;
    }

    if (opcode == OPCODE_RET_IMM16 && Size >= 3) {
        *GadgetSize = 3;
        return GadgetType_RetN;
    }

    if (opcode == OPCODE_SYSCALL_0F && Size >= 2 && Bytes[1] == OPCODE_SYSCALL_05) {
        *GadgetSize = 2;
        return GadgetType_Syscall;
    }

    if (opcode == OPCODE_SYSENTER_0F && Size >= 2 && Bytes[1] == OPCODE_SYSENTER_34) {
        *GadgetSize = 2;
        return GadgetType_Syscall;
    }

    if (opcode == OPCODE_INT && Size >= 2) {
        *GadgetSize = 2;
        return GadgetType_Int;
    }

    //
    // FF-prefix: JMP/CALL reg/mem with proper ModR/M decoding
    //
    if (opcode == OPCODE_FF_PREFIX && Size >= 2) {
        modrm = Bytes[1];
        reg = (modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT;
        mod = (modrm & MODRM_MOD_MASK) >> 6;

        modrmLen = RoppDecodeModRMLength(Bytes + 1, Size - 1);
        if (modrmLen == 0) {
            return GadgetType_Unknown;
        }

        *GadgetSize = 1 + modrmLen;  // opcode + modrm+sib+disp

        switch (reg) {
        case FF_CALL_REG:
            return (mod == 3) ? GadgetType_CallReg : GadgetType_CallMem;

        case FF_JMP_REG:
            return (mod == 3) ? GadgetType_JmpReg : GadgetType_JmpMem;

        case FF_CALL_MEM:
            return GadgetType_CallMem;

        case FF_JMP_MEM:
            return GadgetType_JmpMem;
        }
    }

    return GadgetType_Unknown;
}


static
VOID
RoppAnalyzeGadgetSemantics(
    PROP_GADGET Gadget
    )
/*++

Routine Description:

    Performs semantic analysis on a gadget to determine what
    registers and memory it affects. Correct PUSH/POP semantics:
    - PUSH reads the source register, modifies RSP
    - POP writes the destination register, modifies RSP

--*/
{
    PUCHAR bytes;
    ULONG size;
    ULONG i;
    UCHAR opcode;
    UCHAR modrm;

    if (Gadget == NULL || Gadget->Size == 0) {
        return;
    }

    bytes = Gadget->Bytes;
    size = Gadget->Size;

    for (i = 0; i < size; i++) {
        opcode = bytes[i];

        //
        // PUSH r64 (0x50-0x57): reads source register, modifies RSP
        //
        if (opcode >= 0x50 && opcode <= 0x57) {
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= REG_RSP;
            Gadget->Semantics.RegistersRead |= (1 << (opcode - 0x50));
        }
        //
        // POP r64 (0x58-0x5F): writes destination register, modifies RSP
        //
        else if (opcode >= 0x58 && opcode <= 0x5F) {
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= REG_RSP;
            Gadget->Semantics.RegistersModified |= (1 << (opcode - 0x58));
        }
        //
        // MOV r/m, r (0x89) or MOV r, r/m (0x8B)
        //
        else if ((opcode == 0x89 || opcode == 0x8B) && (i + 1 < size)) {
            modrm = bytes[i + 1];
            if ((modrm & MODRM_MOD_MASK) != 0xC0) {
                if (opcode == 0x89) {
                    Gadget->Semantics.WritesMemory = TRUE;
                } else {
                    Gadget->Semantics.ReadsMemory = TRUE;
                }
            }
            i++;  // skip ModR/M
        }
        //
        // XCHG rAX, rSP (0x94) — stack pivot
        //
        else if (opcode == 0x94) {
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= (REG_RAX | REG_RSP);
        }
        //
        // RET/RETF/RETN — terminal, stop analysis
        //
        else if (opcode == OPCODE_RET || opcode == OPCODE_RET_IMM16 ||
                 opcode == OPCODE_RETF || opcode == OPCODE_RETF_IMM16) {
            break;
        }
    }
}


static
ULONG
RoppCalculateDangerScore(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_GADGET Gadget
    )
{
    ULONG score = 0;
    ULONG i;

    if (Gadget == NULL) {
        return 0;
    }

    switch (Gadget->Type) {
    case GadgetType_Syscall:
        score += 80;
        Gadget->IsPrivileged = TRUE;
        break;
    case GadgetType_Ret:
    case GadgetType_RetN:
        score += 10;
        break;
    case GadgetType_JmpReg:
    case GadgetType_CallReg:
        score += 30;
        Gadget->CouldBypassCFG = TRUE;
        break;
    case GadgetType_JmpMem:
    case GadgetType_CallMem:
        score += 40;
        break;
    case GadgetType_Int:
        score += 50;
        break;
    default:
        break;
    }

    if (Gadget->Semantics.ModifiesStack) {
        score += 20;
    }
    if (Gadget->Semantics.WritesMemory) {
        score += 15;
    }
    if (Gadget->Semantics.RegistersModified & REG_RSP) {
        score += 40;
    }

    for (i = 0; i < Detector->DangerousPatternCount; i++) {
        if (Gadget->Size >= Detector->DangerousPatterns[i].PatternSize) {
            if (RtlCompareMemory(
                    Gadget->Bytes,
                    Detector->DangerousPatterns[i].Pattern,
                    Detector->DangerousPatterns[i].PatternSize
                    ) == Detector->DangerousPatterns[i].PatternSize) {
                score += Detector->DangerousPatterns[i].DangerScore;
            }
        }
    }

    return min(score, 100);
}


static
VOID
RoppInitializeDangerousPatterns(
    PROP_DETECTOR_INTERNAL Detector
    )
{
    ULONG idx = 0;

    // XCHG EAX, ESP / XCHG RAX, RSP — stack pivot
    Detector->DangerousPatterns[idx].Pattern[0] = 0x94;
    Detector->DangerousPatterns[idx].PatternSize = 1;
    Detector->DangerousPatterns[idx].DangerScore = 50;
    Detector->DangerousPatterns[idx].Description = "Stack pivot XCHG";
    idx++;

    // MOV ESP, EAX / MOV RSP, RAX — stack pivot
    Detector->DangerousPatterns[idx].Pattern[0] = 0x89;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC4;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 50;
    Detector->DangerousPatterns[idx].Description = "Stack pivot MOV";
    idx++;

    // LEAVE; RET
    Detector->DangerousPatterns[idx].Pattern[0] = 0xC9;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 25;
    Detector->DangerousPatterns[idx].Description = "LEAVE; RET sequence";
    idx++;

    // POP RDI; RET
    Detector->DangerousPatterns[idx].Pattern[0] = 0x5F;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 15;
    Detector->DangerousPatterns[idx].Description = "POP RDI; RET";
    idx++;

    // POP RSI; RET
    Detector->DangerousPatterns[idx].Pattern[0] = 0x5E;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 15;
    Detector->DangerousPatterns[idx].Description = "POP RSI; RET";
    idx++;

    // POP RDX; RET
    Detector->DangerousPatterns[idx].Pattern[0] = 0x5A;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 15;
    Detector->DangerousPatterns[idx].Description = "POP RDX; RET";
    idx++;

    // JMP RSP
    Detector->DangerousPatterns[idx].Pattern[0] = 0xFF;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xE4;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 60;
    Detector->DangerousPatterns[idx].Description = "JMP RSP";
    idx++;

    // CALL RSP
    Detector->DangerousPatterns[idx].Pattern[0] = 0xFF;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xD4;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 60;
    Detector->DangerousPatterns[idx].Description = "CALL RSP";
    idx++;

    // ADD RSP, imm8
    Detector->DangerousPatterns[idx].Pattern[0] = 0x48;
    Detector->DangerousPatterns[idx].Pattern[1] = 0x83;
    Detector->DangerousPatterns[idx].Pattern[2] = 0xC4;
    Detector->DangerousPatterns[idx].PatternSize = 3;
    Detector->DangerousPatterns[idx].DangerScore = 20;
    Detector->DangerousPatterns[idx].Description = "ADD RSP, imm8";
    idx++;

    Detector->DangerousPatternCount = idx;
}

//=============================================================================
// Private Functions - Stack Analysis
//=============================================================================

static
NTSTATUS
RoppInitializeAnalysisContext(
    PROP_DETECTOR_INTERNAL Detector,
    HANDLE ProcessId,
    HANDLE ThreadId,
    PCONTEXT ThreadContext,
    PROP_ANALYSIS_CONTEXT Context
    )
/*++

Routine Description:

    Initializes analysis context with real stack information.
    Retrieves stack base/limit from the target thread's TEB.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    KAPC_STATE apcState;
    PTEB teb = NULL;

    RtlZeroMemory(Context, sizeof(ROP_ANALYSIS_CONTEXT));

    Context->Detector = Detector;
    Context->ProcessId = ProcessId;
    Context->ThreadId = ThreadId;
    Context->TimeoutMs = ROP_ANALYSIS_TIMEOUT_MS;

    KeQuerySystemTime(&Context->StartTime);

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
    // Use ThreadContext if provided (contains Rsp)
    //
    if (ThreadContext != NULL) {
#ifdef _AMD64_
        Context->CurrentSp = (PVOID)ThreadContext->Rsp;
#else
        Context->CurrentSp = (PVOID)ThreadContext->Esp;
#endif
    }

    //
    // Get stack limits from TEB by attaching to the target process.
    // For kernel threads, use IoGetStackLimits.
    //
    if (PsIsSystemThread(thread)) {
        //
        // Kernel thread: use IoGetStackLimits (only valid for current thread)
        //
        if (thread == PsGetCurrentThread()) {
            ULONG_PTR lowLimit, highLimit;
            IoGetStackLimits(&lowLimit, &highLimit);
            Context->StackLimit = (PVOID)lowLimit;
            Context->StackBase = (PVOID)highLimit;
        } else {
            //
            // Cannot directly read another kernel thread's stack limits.
            // Use a conservative estimate from the initial stack.
            //
            PVOID initialStack = IoGetInitialStack();
            if (initialStack != NULL) {
                Context->StackBase = initialStack;
                Context->StackLimit = (PVOID)((ULONG_PTR)initialStack - ROP_KERNEL_STACK_SIZE_ESTIMATE);
            }
        }
    } else {
        //
        // User-mode thread: read stack limits from TEB
        //
        KeStackAttachProcess(process, &apcState);

        __try {
            teb = (PTEB)PsGetThreadTeb(thread);
            if (teb != NULL) {
                ProbeForRead(teb, sizeof(TEB), sizeof(UCHAR));
                Context->StackBase = teb->NtTib.StackBase;
                Context->StackLimit = teb->NtTib.StackLimit;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            //
            // TEB read failed — will be caught later as NULL stack bounds
            //
        }

        KeUnstackDetachProcess(&apcState);
    }

    //
    // If we still don't have a CurrentSp but we do have stack bounds,
    // default to StackLimit (top of committed stack, low address).
    //
    if (Context->CurrentSp == NULL && Context->StackLimit != NULL) {
        Context->CurrentSp = Context->StackLimit;
    }

    ObDereferenceObject(thread);
    ObDereferenceObject(process);

    //
    // Validate we have enough information to proceed
    //
    if (Context->StackBase == NULL || Context->CurrentSp == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if ((ULONG_PTR)Context->CurrentSp >= (ULONG_PTR)Context->StackBase) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}


static
VOID
RoppCleanupAnalysisContext(
    PROP_ANALYSIS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (Context->StackBuffer != NULL) {
        ShadowStrikeSecureFree(
            Context->StackBuffer,
            Context->StackBufferSize,
            ROP_POOL_TAG_CONTEXT
            );
        Context->StackBuffer = NULL;
    }
}


static
NTSTATUS
RoppCaptureStack(
    PROP_ANALYSIS_CONTEXT Context
    )
/*++

Routine Description:

    Captures stack contents for analysis.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    SIZE_T availableStack;
    SIZE_T bytesToCopy;
    SIZE_T bytesCopied = 0;

    if (Context->CurrentSp == NULL || Context->StackBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Calculate available stack size with overflow check
    //
    if ((ULONG_PTR)Context->StackBase <= (ULONG_PTR)Context->CurrentSp) {
        return STATUS_INVALID_PARAMETER;
    }

    availableStack = (SIZE_T)((PUCHAR)Context->StackBase - (PUCHAR)Context->CurrentSp);
    bytesToCopy = min(ROP_STACK_SAMPLE_SIZE, availableStack);

    if (bytesToCopy == 0 || bytesToCopy < sizeof(ULONG_PTR)) {
        return STATUS_NO_DATA_DETECTED;
    }

    //
    // Allocate stack buffer
    //
    Context->StackBufferSize = bytesToCopy;
    Context->StackBuffer = (PULONG_PTR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Context->StackBufferSize,
        ROP_POOL_TAG_CONTEXT
        );

    if (Context->StackBuffer == NULL) {
        Context->StackBufferSize = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Attach to target process and copy stack
    //
    status = PsLookupProcessByProcessId(Context->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(Context->StackBuffer, ROP_POOL_TAG_CONTEXT);
        Context->StackBuffer = NULL;
        Context->StackBufferSize = 0;
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead(Context->CurrentSp, bytesToCopy, sizeof(UCHAR));
        RtlCopyMemory(Context->StackBuffer, Context->CurrentSp, bytesToCopy);
        bytesCopied = bytesToCopy;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(Context->StackBuffer, ROP_POOL_TAG_CONTEXT);
        Context->StackBuffer = NULL;
        Context->StackBufferSize = 0;
    } else {
        Context->StackBufferSize = bytesCopied;
    }

    return status;
}


static
NTSTATUS
RoppBuildModuleCache(
    PROP_ANALYSIS_CONTEXT Context
    )
/*++

Routine Description:

    Builds a cache of loaded modules for fast executable address lookups.
    Enumerates the target process's loaded module list via PEB->Ldr.

--*/
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PPEB peb = NULL;
    PPEB_LDR_DATA ldr = NULL;
    PLIST_ENTRY head = NULL;
    PLIST_ENTRY current = NULL;
    PLDR_DATA_TABLE_ENTRY ldrEntry = NULL;
    ULONG count = 0;
    ULONG maxModules = ARRAYSIZE(Context->ModuleCache);

    Context->ModuleCacheCount = 0;

    status = PsLookupProcessByProcessId(Context->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // For system process, populate from kernel module list
    //
    if (PsGetProcessId(process) == (HANDLE)(ULONG_PTR)4) {
        ObDereferenceObject(process);
        //
        // Kernel-mode addresses are validated via ShadowStrikeIsKernelAddress
        // which covers system-loaded drivers. Process-specific module enumeration
        // is not applicable to the System process (PID 4) since it has no PEB.
        //
        return STATUS_SUCCESS;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        peb = PsGetProcessPeb(process);
        if (peb == NULL) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        ProbeForRead(peb, sizeof(PEB), sizeof(UCHAR));
        ldr = peb->Ldr;
        if (ldr == NULL) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        ProbeForRead(ldr, sizeof(PEB_LDR_DATA), sizeof(UCHAR));
        head = &ldr->InMemoryOrderModuleList;
        current = head->Flink;

        while (current != head && count < maxModules) {
            ProbeForRead(current, sizeof(LIST_ENTRY), sizeof(UCHAR));

            ldrEntry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(UCHAR));

            if (ldrEntry->DllBase != NULL && ldrEntry->SizeOfImage > 0) {
                Context->ModuleCache[count].Base = ldrEntry->DllBase;
                Context->ModuleCache[count].Size = ldrEntry->SizeOfImage;
                Context->ModuleCache[count].IsExecutable = TRUE;

                //
                // Copy a truncated module name for diagnostics
                //
                if (ldrEntry->BaseDllName.Buffer != NULL &&
                    ldrEntry->BaseDllName.Length > 0) {
                    USHORT copyLen = min(
                        ldrEntry->BaseDllName.Length,
                        (USHORT)(sizeof(Context->ModuleCache[count].Name) - sizeof(WCHAR))
                        );
                    ProbeForRead(ldrEntry->BaseDllName.Buffer, copyLen, sizeof(UCHAR));
                    RtlCopyMemory(
                        Context->ModuleCache[count].Name,
                        ldrEntry->BaseDllName.Buffer,
                        copyLen
                        );
                    Context->ModuleCache[count].Name[copyLen / sizeof(WCHAR)] = L'\0';
                }

                count++;
            }

            current = current->Flink;
        }

        Context->ModuleCacheCount = count;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Partial cache is still useful — use what we got
        //
        Context->ModuleCacheCount = count;
        status = STATUS_SUCCESS;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}


static
BOOLEAN
RoppIsExecutableAddress(
    PROP_ANALYSIS_CONTEXT Context,
    PVOID Address
    )
/*++

Routine Description:

    Checks if an address falls within a known executable module.
    Returns FALSE for addresses not in any known module.

--*/
{
    ULONG i;

    for (i = 0; i < Context->ModuleCacheCount; i++) {
        if ((ULONG_PTR)Address >= (ULONG_PTR)Context->ModuleCache[i].Base &&
            (ULONG_PTR)Address < (ULONG_PTR)Context->ModuleCache[i].Base +
                                  Context->ModuleCache[i].Size) {
            return Context->ModuleCache[i].IsExecutable;
        }
    }

    //
    // For kernel-mode addresses, check against kernel module range.
    // User-mode addresses not in any cached module are NOT executable.
    //
    if (ShadowStrikeIsKernelAddress(Address)) {
        return TRUE;
    }

    return FALSE;
}

//=============================================================================
// Private Functions - Chain Detection
//=============================================================================

static
NTSTATUS
RoppDetectChain(
    PROP_ANALYSIS_CONTEXT Context,
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Analyzes captured stack for gadget chains.
    Only increments UnknownGadgets for addresses that ARE in executable
    modules but are NOT in the gadget database (not every random stack value).

--*/
{
    NTSTATUS status;
    PULONG_PTR stackPtr;
    SIZE_T slotCount;
    SIZE_T i;
    ULONG_PTR value;
    ROP_GADGET gadgetCopy;
    PROP_CHAIN_ENTRY chainEntry;
    ULONG consecutiveGadgets = 0;
    ULONG maxConsecutive = 0;

    if (Context->StackBuffer == NULL || Context->StackBufferSize == 0) {
        return STATUS_NO_DATA_DETECTED;
    }

    stackPtr = Context->StackBuffer;
    slotCount = Context->StackBufferSize / sizeof(ULONG_PTR);

    for (i = 0; i < slotCount; i++) {
        value = stackPtr[i];

        if (value < 0x10000 || value == (ULONG_PTR)-1) {
            if (consecutiveGadgets > 0) {
                maxConsecutive = max(maxConsecutive, consecutiveGadgets);
            }
            consecutiveGadgets = 0;
            continue;
        }

        //
        // Check if this address is in an executable module
        //
        if (!RoppIsExecutableAddress(Context, (PVOID)value)) {
            Context->NonExecutableAddresses++;
            consecutiveGadgets = 0;
            continue;
        }

        //
        // Look up in gadget database (copy-out, no lifetime issue)
        //
        status = RopLookupGadget(
            &Context->Detector->Public,
            (PVOID)value,
            &gadgetCopy
            );

        if (NT_SUCCESS(status)) {
            consecutiveGadgets++;
            Context->TotalGadgets++;

            status = RoppAllocateChainEntry(&chainEntry);
            if (NT_SUCCESS(status)) {
                chainEntry->GadgetAddress = (PVOID)value;
                chainEntry->GadgetType = gadgetCopy.Type;
                chainEntry->GadgetSize = gadgetCopy.Size;
                chainEntry->GadgetDangerScore = gadgetCopy.DangerScore;
                chainEntry->GadgetIsPrivileged = gadgetCopy.IsPrivileged;
                chainEntry->GadgetRegistersModified = gadgetCopy.Semantics.RegistersModified;
                chainEntry->StackOffset = i * sizeof(ULONG_PTR);
                chainEntry->StackValue = value;
                chainEntry->Index = Result->ChainLength;

                InsertTailList(&Result->ChainEntries, &chainEntry->ListEntry);
                Result->ChainLength++;
            }
        } else {
            //
            // Address is in an executable module but not in our gadget DB.
            // This is a real "unknown executable address" (legitimate
            // return address or unindexed gadget).
            //
            Context->UnknownAddresses++;

            if (consecutiveGadgets > 0 &&
                consecutiveGadgets < Context->Detector->Public.Config.MinChainLength) {
                maxConsecutive = max(maxConsecutive, consecutiveGadgets);
                consecutiveGadgets = 0;
            }
        }

        if (consecutiveGadgets >= Context->Detector->Public.Config.MinChainLength) {
            Result->ChainDetected = TRUE;
        }

        if (Result->ChainLength >= Context->Detector->Public.Config.MaxChainLength) {
            break;
        }
    }

    maxConsecutive = max(maxConsecutive, consecutiveGadgets);
    Result->UniqueGadgets = Context->TotalGadgets;
    Result->UnknownGadgets = Context->UnknownAddresses;

    return STATUS_SUCCESS;
}


static
BOOLEAN
RoppDetectStackPivot(
    PROP_ANALYSIS_CONTEXT Context,
    PPVOID PivotSource,
    PPVOID PivotDestination
    )
{
    ULONG_PTR currentSp;
    ULONG_PTR stackBase;
    ULONG_PTR stackLimit;

    if (Context->CurrentSp == NULL || Context->StackBase == NULL) {
        return FALSE;
    }

    currentSp = (ULONG_PTR)Context->CurrentSp;
    stackBase = (ULONG_PTR)Context->StackBase;
    stackLimit = (ULONG_PTR)Context->StackLimit;

    //
    // SP outside normal stack bounds indicates a pivot
    //
    if (stackLimit != 0 && (currentSp < stackLimit || currentSp > stackBase)) {
        if (PivotSource != NULL) {
            *PivotSource = Context->StackBase;
        }
        if (PivotDestination != NULL) {
            *PivotDestination = Context->CurrentSp;
        }
        return TRUE;
    }

    return FALSE;
}


static
ROP_ATTACK_TYPE
RoppClassifyAttack(
    PROP_DETECTION_RESULT Result
    )
{
    PLIST_ENTRY entry;
    PROP_CHAIN_ENTRY chainEntry;
    ULONG retCount = 0;
    ULONG jmpCount = 0;
    ULONG callCount = 0;
    ULONG syscallCount = 0;

    if (!Result->ChainDetected) {
        return RopAttack_Unknown;
    }

    for (entry = Result->ChainEntries.Flink;
         entry != &Result->ChainEntries;
         entry = entry->Flink) {

        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);

        switch (chainEntry->GadgetType) {
        case GadgetType_Ret:
        case GadgetType_RetN:
            retCount++;
            break;
        case GadgetType_JmpReg:
        case GadgetType_JmpMem:
            jmpCount++;
            break;
        case GadgetType_CallReg:
        case GadgetType_CallMem:
            callCount++;
            break;
        case GadgetType_Syscall:
            syscallCount++;
            break;
        default:
            break;
        }
    }

    if (Result->StackPivotDetected) {
        return RopAttack_StackPivot;
    }

    if (syscallCount > 0) {
        return RopAttack_SROP;
    }

    if (retCount > jmpCount && retCount > callCount) {
        return RopAttack_ROP;
    }

    if (jmpCount > retCount && jmpCount > callCount) {
        return RopAttack_JOP;
    }

    if (callCount > retCount && callCount > jmpCount) {
        return RopAttack_COP;
    }

    if (retCount > 0 && (jmpCount > 0 || callCount > 0)) {
        return RopAttack_Mixed;
    }

    return RopAttack_ROP;
}


static
VOID
RoppCalculateConfidence(
    PROP_DETECTION_RESULT Result
    )
{
    ULONG confidence = 0;
    ULONG severity = 0;
    PLIST_ENTRY entry;
    PROP_CHAIN_ENTRY chainEntry;
    ULONG dangerousGadgets = 0;
    ULONG totalDangerScore = 0;

    if (!Result->ChainDetected) {
        Result->ConfidenceScore = 0;
        Result->SeverityScore = 0;
        return;
    }

    if (Result->ChainLength >= 10) {
        confidence = 90;
    } else if (Result->ChainLength >= 5) {
        confidence = 70;
    } else if (Result->ChainLength >= 3) {
        confidence = 50;
    }

    if (Result->StackPivotDetected) {
        confidence = min(100, confidence + 20);
    }

    for (entry = Result->ChainEntries.Flink;
         entry != &Result->ChainEntries;
         entry = entry->Flink) {

        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);

        totalDangerScore += chainEntry->GadgetDangerScore;

        if (chainEntry->GadgetDangerScore >= 50) {
            dangerousGadgets++;
        }
        if (chainEntry->GadgetIsPrivileged) {
            severity = max(severity, 80);
        }
    }

    if (Result->ChainLength > 0) {
        severity = max(severity, totalDangerScore / Result->ChainLength);
    }

    if (dangerousGadgets >= 3) {
        severity = min(100, severity + 20);
    }

    switch (Result->AttackType) {
    case RopAttack_SROP:
        severity = max(severity, 90);
        break;
    case RopAttack_StackPivot:
        severity = max(severity, 80);
        break;
    default:
        break;
    }

    Result->ConfidenceScore = min(confidence, 100);
    Result->SeverityScore = min(severity, 100);
}

//=============================================================================
// Private Functions - Payload Inference
//=============================================================================

static
VOID
RoppInferPayload(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Infers what the ROP chain payload might do based on gadget characteristics.
    Detects VirtualProtect/VirtualAlloc patterns by checking for sequences that
    set up multiple argument registers (typical of Windows API calls).

--*/
{
    PLIST_ENTRY entry;
    PROP_CHAIN_ENTRY chainEntry;
    BOOLEAN hasSyscall = FALSE;
    BOOLEAN hasStackPivot = FALSE;
    BOOLEAN hasMultiArgSetup = FALSE;
    ULONG argRegistersSet = 0;
    ULONG consecutiveArgSetups = 0;

    UNREFERENCED_PARAMETER(Detector);

    if (!Result->ChainDetected) {
        return;
    }

    Result->PayloadAnalysis.PayloadInferred = FALSE;

    //
    // Analyze chain for payload patterns
    //
    for (entry = Result->ChainEntries.Flink;
         entry != &Result->ChainEntries;
         entry = entry->Flink) {

        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);

        if (chainEntry->GadgetType == GadgetType_Syscall) {
            hasSyscall = TRUE;
        }

        if (chainEntry->GadgetRegistersModified & REG_RSP) {
            hasStackPivot = TRUE;
        }

        //
        // Detect API argument setup:
        // Windows x64 calling convention uses RCX, RDX, R8, R9.
        // If the chain sets up 3+ of these, it is likely calling a
        // function like VirtualProtect(addr, size, protect, &old).
        //
        if (chainEntry->GadgetRegistersModified & REG_RCX) {
            argRegistersSet |= REG_RCX;
            consecutiveArgSetups++;
        }
        if (chainEntry->GadgetRegistersModified & REG_RDX) {
            argRegistersSet |= REG_RDX;
            consecutiveArgSetups++;
        }
        if (chainEntry->GadgetRegistersModified & REG_R8) {
            argRegistersSet |= REG_R8;
            consecutiveArgSetups++;
        }
        if (chainEntry->GadgetRegistersModified & REG_R9) {
            argRegistersSet |= REG_R9;
            consecutiveArgSetups++;
        }
    }

    //
    // Count how many x64 calling convention arg registers are set
    //
    {
        ULONG argCount = 0;
        if (argRegistersSet & REG_RCX) argCount++;
        if (argRegistersSet & REG_RDX) argCount++;
        if (argRegistersSet & REG_R8)  argCount++;
        if (argRegistersSet & REG_R9)  argCount++;

        if (argCount >= 3) {
            hasMultiArgSetup = TRUE;
        }
    }

    Result->PayloadAnalysis.PayloadInferred = TRUE;

    if (hasSyscall) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Direct syscall chain - likely attempting to bypass security hooks"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
        Result->PayloadAnalysis.MayDisableDefenses = TRUE;
        Result->PayloadAnalysis.MayEscalatePrivileges = TRUE;
    } else if (hasStackPivot && hasMultiArgSetup) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Stack pivot with API argument setup - likely VirtualProtect/VirtualAlloc for shellcode"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
        Result->PayloadAnalysis.MayDisableDefenses = TRUE;
    } else if (hasMultiArgSetup) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Multi-argument API call chain - possible memory manipulation (VirtualProtect/VirtualAlloc)"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    } else if (hasStackPivot) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Stack pivot detected - execution flow hijacked to attacker-controlled memory"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    } else {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Generic ROP chain - purpose unclear, potential code execution"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    }
}


//=============================================================================
// Private Functions - Callback Notification
//=============================================================================

static
VOID
RoppNotifyCallbacks(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Notifies all registered callbacks of a detection.
    Uses per-callback rundown protection so callbacks can be safely
    unregistered even while notification is in progress.

--*/
{
    PLIST_ENTRY entry;
    PROP_CALLBACK_ENTRY callbackEntry;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (entry = Detector->CallbackList.Flink;
         entry != &Detector->CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, ROP_CALLBACK_ENTRY, ListEntry);

        if (callbackEntry->Active) {
            //
            // Acquire per-callback rundown protection.
            // If unregister is pending, this will fail and we skip.
            //
            if (ExAcquireRundownProtection(&callbackEntry->RundownRef)) {
                __try {
                    callbackEntry->Callback(Result, callbackEntry->Context);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    //
                    // Callback threw exception — continue with remaining
                    //
                }
                ExReleaseRundownProtection(&callbackEntry->RundownRef);
            }
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}


//=============================================================================
// Private Functions - Rate Limiting
//=============================================================================

static
BOOLEAN
RoppCheckRateLimit(
    PROP_DETECTOR_INTERNAL Detector
    )
/*++

Routine Description:

    Checks if analysis rate limit allows another analysis.
    Uses compare-exchange to avoid TOCTOU on the reset.

--*/
{
    LARGE_INTEGER currentTime;
    LONG64 lastReset;
    LONG64 elapsed;
    LONG64 count;

    KeQuerySystemTime(&currentTime);

    lastReset = InterlockedCompareExchange64(
        &Detector->LastResetTime,
        0, 0  // Just read
        );

    elapsed = (currentTime.QuadPart - lastReset) / 10000000;

    if (elapsed >= 1) {
        //
        // Attempt atomic reset. Only one thread wins the CAS.
        //
        if (InterlockedCompareExchange64(
                &Detector->LastResetTime,
                currentTime.QuadPart,
                lastReset
                ) == lastReset) {
            InterlockedExchange64(&Detector->AnalysisCount, 0);
        }
    }

    count = InterlockedIncrement64(&Detector->AnalysisCount);

    return (count <= (LONG64)Detector->MaxAnalysesPerSecond);
}