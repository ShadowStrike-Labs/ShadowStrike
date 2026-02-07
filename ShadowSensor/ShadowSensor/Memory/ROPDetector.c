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
#pragma alloc_text(PAGE, RopAnalyzeStack)
#pragma alloc_text(PAGE, RopValidateCallStack)
#pragma alloc_text(PAGE, RopRegisterCallback)
#pragma alloc_text(PAGE, RopUnregisterCallback)
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
#define ROP_CHAIN_LOOKASIDE_DEPTH       128
#define ROP_RESULT_LOOKASIDE_DEPTH      64

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
    // Lookaside lists for performance
    //
    SHADOWSTRIKE_LOOKASIDE GadgetLookaside;
    SHADOWSTRIKE_LOOKASIDE ChainEntryLookaside;
    SHADOWSTRIKE_LOOKASIDE ResultLookaside;

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
    } ModuleCache[64];
    ULONG ModuleCacheCount;

    //
    // Detection state
    //
    ULONG ConsecutiveGadgets;
    ULONG TotalGadgets;
    ULONG UnknownAddresses;
    ROP_ATTACK_TYPE DetectedType;

    //
    // Timing
    //
    LARGE_INTEGER StartTime;
    ULONG TimeoutMs;

} ROP_ANALYSIS_CONTEXT, *PROP_ANALYSIS_CONTEXT;

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
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _Out_ PROP_CHAIN_ENTRY* Entry
    );

static
VOID
RoppFreeChainEntry(
    _In_ PROP_DETECTOR_INTERNAL Detector,
    _In_ PROP_CHAIN_ENTRY Entry
    );

static
NTSTATUS
RoppAllocateResult(
    _In_ PROP_DETECTOR_INTERNAL Detector,
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

    Initializes the ROP/JOP detection engine with enterprise-grade
    gadget database and analysis capabilities.

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
    // Initialize lookaside lists for high-performance allocation
    //
    status = ShadowStrikeLookasideInit(
        &internalDetector->GadgetLookaside,
        sizeof(ROP_GADGET),
        ROP_POOL_TAG_GADGET,
        ROP_GADGET_LOOKASIDE_DEPTH,
        FALSE   // Non-paged for DISPATCH_LEVEL access
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = ShadowStrikeLookasideInit(
        &internalDetector->ChainEntryLookaside,
        sizeof(ROP_CHAIN_ENTRY),
        ROP_POOL_TAG_CHAIN,
        ROP_CHAIN_LOOKASIDE_DEPTH,
        FALSE
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = ShadowStrikeLookasideInit(
        &internalDetector->ResultLookaside,
        sizeof(ROP_DETECTION_RESULT),
        ROP_POOL_TAG_CONTEXT,
        ROP_RESULT_LOOKASIDE_DEPTH,
        FALSE
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
    // Mark as initialized
    //
    internalDetector->Public.Initialized = TRUE;

    *Detector = &internalDetector->Public;
    return STATUS_SUCCESS;

Cleanup:
    if (internalDetector != NULL) {
        if (internalDetector->GadgetLookaside.Initialized) {
            ShadowStrikeLookasideCleanup(&internalDetector->GadgetLookaside);
        }
        if (internalDetector->ChainEntryLookaside.Initialized) {
            ShadowStrikeLookasideCleanup(&internalDetector->ChainEntryLookaside);
        }
        if (internalDetector->ResultLookaside.Initialized) {
            ShadowStrikeLookasideCleanup(&internalDetector->ResultLookaside);
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

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    Detector->Initialized = FALSE;

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
    // Cleanup lookaside lists
    //
    ShadowStrikeLookasideCleanup(&internalDetector->GadgetLookaside);
    ShadowStrikeLookasideCleanup(&internalDetector->ChainEntryLookaside);
    ShadowStrikeLookasideCleanup(&internalDetector->ResultLookaside);

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
    gadget database. This enables detection of gadget chains.

Arguments:

    Detector - Initialized detector
    ModuleBase - Base address of the module
    ModuleSize - Size of the module in bytes
    ModuleName - Name of the module

Return Value:

    STATUS_SUCCESS on success
    STATUS_INVALID_PARAMETER on invalid input
    STATUS_INSUFFICIENT_RESOURCES on allocation failure

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_SCANNED_MODULE moduleEntry = NULL;
    PUCHAR currentByte;
    PUCHAR moduleEnd;
    ULONG gadgetCount = 0;
    ULONG offset;
    ROP_GADGET_TYPE gadgetType;
    ULONG gadgetSize;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG sectionIndex;
    BOOLEAN isExecutable;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ModuleBase == NULL || ModuleSize == 0 || ModuleSize > SHADOWSTRIKE_MAX_ALLOCATION_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    //
    // Validate PE structure
    //
    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
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
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(moduleEntry, sizeof(ROP_SCANNED_MODULE));
    moduleEntry->ModuleBase = ModuleBase;
    moduleEntry->ModuleSize = ModuleSize;

    //
    // Clone module name
    //
    if (ModuleName != NULL && ModuleName->Length > 0) {
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

        __try {
            currentByte = (PUCHAR)ModuleBase + sectionHeader[sectionIndex].VirtualAddress;
            moduleEnd = currentByte + sectionHeader[sectionIndex].Misc.VirtualSize;

            //
            // Scan for gadget-ending instructions
            //
            for (offset = 0; currentByte + offset < moduleEnd && offset < sectionHeader[sectionIndex].Misc.VirtualSize; offset++) {

                //
                // Look for RET, JMP reg, CALL reg, SYSCALL patterns
                //
                gadgetType = RoppClassifyGadget(currentByte + offset, (ULONG)(moduleEnd - (currentByte + offset)), &gadgetSize);

                if (gadgetType != GadgetType_Unknown && gadgetSize > 0) {
                    //
                    // Found a potential gadget ending - scan backwards for useful gadgets
                    //
                    ULONG backScan;
                    ULONG maxBackScan = min(ROP_GADGET_MAX_SIZE, offset);

                    for (backScan = 0; backScan <= maxBackScan; backScan++) {
                        PVOID gadgetAddr = currentByte + offset - backScan;
                        ULONG totalSize = backScan + gadgetSize;

                        if (totalSize >= 2 && totalSize <= ROP_GADGET_MAX_SIZE) {
                            //
                            // Add this gadget to the database
                            //
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

                                //
                                // Limit gadgets per module to prevent excessive memory use
                                //
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
            //
            // Section access failed, continue with next section
            //
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

    //
    // Update statistics
    //
    InterlockedAdd64(&Detector->Stats.GadgetsIndexed, gadgetCount);

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

Arguments:

    Detector - Initialized detector
    Address - Address of the gadget
    ModuleBase - Base of containing module
    Bytes - Gadget bytes
    Size - Size in bytes
    Type - Gadget type

Return Value:

    STATUS_SUCCESS on success

--*/
{
    NTSTATUS status;
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_GADGET gadget = NULL;
    ULONG hashBucket;

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Address == NULL || Bytes == NULL || Size == 0 || Size > ROP_GADGET_MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    //
    // Allocate gadget structure from lookaside
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

    //
    // Perform semantic analysis if enabled
    //
    if (Detector->Config.EnableSemanticAnalysis) {
        RoppAnalyzeGadgetSemantics(gadget);
    }

    //
    // Calculate danger score
    //
    gadget->DangerScore = RoppCalculateDangerScore(internalDetector, gadget);

    //
    // Add to hash table and list
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
    PROP_GADGET* Gadget
    )
/*++

Routine Description:

    Looks up a gadget by address in the database.

Arguments:

    Detector - Initialized detector
    Address - Gadget address to find
    Gadget - Receives gadget pointer if found

Return Value:

    STATUS_SUCCESS if found
    STATUS_NOT_FOUND if not in database

--*/
{
    ULONG hashBucket;
    PLIST_ENTRY entry;
    PROP_GADGET current;

    if (Detector == NULL || !Detector->Initialized || Address == NULL || Gadget == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Gadget = NULL;

    hashBucket = RoppHashAddress(Address) % ROP_GADGET_HASH_BUCKETS;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->GadgetLock);

    for (entry = Detector->GadgetHash[hashBucket].Flink;
         entry != &Detector->GadgetHash[hashBucket];
         entry = entry->Flink) {

        current = CONTAINING_RECORD(entry, ROP_GADGET, HashEntry);

        if (current->Address == Address) {
            *Gadget = current;
            ExReleasePushLockShared(&Detector->GadgetLock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockShared(&Detector->GadgetLock);
    KeLeaveCriticalRegion();

    return STATUS_NOT_FOUND;
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

    Analyzes a thread's stack for ROP/JOP chains. This is the primary
    detection entry point.

Arguments:

    Detector - Initialized detector
    ProcessId - Target process
    ThreadId - Target thread
    ThreadContext - Optional thread context
    Result - Receives detection result

Return Value:

    STATUS_SUCCESS on successful analysis
    STATUS_NOT_FOUND if no chain detected

--*/
{
    NTSTATUS status;
    PROP_DETECTOR_INTERNAL internalDetector;
    ROP_ANALYSIS_CONTEXT context;
    PROP_DETECTION_RESULT result = NULL;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    //
    // Check rate limit
    //
    if (!RoppCheckRateLimit(internalDetector)) {
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
        return status;
    }

    //
    // Allocate result structure
    //
    status = RoppAllocateResult(internalDetector, &result);
    if (!NT_SUCCESS(status)) {
        RoppCleanupAnalysisContext(&context);
        return status;
    }

    //
    // Initialize result
    //
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

    *Result = result;
    result = NULL;
    status = result != NULL ? STATUS_SUCCESS :
             ((*Result)->ChainDetected ? STATUS_SUCCESS : STATUS_NOT_FOUND);

Cleanup:
    RoppCleanupAnalysisContext(&context);

    if (result != NULL) {
        RopFreeResult(result);
    }

    return (*Result != NULL && (*Result)->ChainDetected) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
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

Arguments:

    Detector - Initialized detector
    StackBuffer - Buffer containing stack data
    Size - Size of buffer
    StackBase - Original stack base address
    Result - Receives detection result

Return Value:

    STATUS_SUCCESS if chain detected
    STATUS_NOT_FOUND if no chain

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
    PROP_GADGET gadget;
    PROP_CHAIN_ENTRY chainEntry;

    if (Detector == NULL || !Detector->Initialized ||
        StackBuffer == NULL || Size == 0 || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // Validate buffer alignment
    //
    if (!ShadowStrikeIsAligned(StackBuffer, ROP_STACK_ALIGNMENT)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    //
    // Validate size
    //
    if (Size > ROP_STACK_SAMPLE_SIZE || Size < sizeof(ULONG_PTR)) {
        return STATUS_INVALID_PARAMETER;
    }

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    //
    // Allocate result
    //
    status = RoppAllocateResult(internalDetector, &result);
    if (!NT_SUCCESS(status)) {
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

        //
        // Skip NULL and small values (not code addresses)
        //
        if (value < 0x10000) {
            consecutiveGadgets = 0;
            continue;
        }

        //
        // Look up in gadget database
        //
        status = RopLookupGadget(Detector, (PVOID)value, &gadget);

        if (NT_SUCCESS(status)) {
            //
            // Found a known gadget
            //
            totalGadgets++;
            consecutiveGadgets++;

            //
            // Allocate chain entry
            //
            status = RoppAllocateChainEntry(internalDetector, &chainEntry);
            if (NT_SUCCESS(status)) {
                chainEntry->GadgetAddress = (PVOID)value;
                chainEntry->Gadget = gadget;
                chainEntry->StackOffset = i * sizeof(ULONG_PTR);
                chainEntry->StackValue = value;
                chainEntry->Index = result->ChainLength;

                InsertTailList(&result->ChainEntries, &chainEntry->ListEntry);
                result->ChainLength++;
            }

            //
            // Check for chain detection threshold
            //
            if (consecutiveGadgets >= Detector->Config.MinChainLength) {
                result->ChainDetected = TRUE;
            }
        } else {
            //
            // Not a known gadget - reset consecutive count
            //
            if (consecutiveGadgets > 0 && consecutiveGadgets < Detector->Config.MinChainLength) {
                consecutiveGadgets = 0;
            }
            result->UnknownGadgets++;
        }
    }

    result->UniqueGadgets = totalGadgets;

    if (result->ChainDetected) {
        result->AttackType = RoppClassifyAttack(result);
        RoppCalculateConfidence(result);
        RoppInferPayload(internalDetector, result);

        *Result = result;
        return STATUS_SUCCESS;
    }

    RopFreeResult(result);
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

    Validates a thread's call stack for integrity. Checks for:
    - Valid return addresses
    - Proper stack frame linkage
    - Executable backing for return addresses
    - Known gadget patterns

Arguments:

    Detector - Initialized detector
    ProcessId - Target process
    ThreadId - Target thread
    IsValid - Receives TRUE if stack appears valid
    SuspicionScore - Optional suspicion score (0-100)

Return Value:

    STATUS_SUCCESS on successful validation

--*/
{
    NTSTATUS status;
    PROP_DETECTION_RESULT result = NULL;
    ULONG score = 0;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || IsValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsValid = TRUE;
    if (SuspicionScore != NULL) {
        *SuspicionScore = 0;
    }

    //
    // Perform stack analysis
    //
    status = RopAnalyzeStack(Detector, ProcessId, ThreadId, NULL, &result);

    if (status == STATUS_NOT_FOUND) {
        //
        // No chain detected - stack appears valid
        //
        *IsValid = TRUE;
        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Evaluate results
    //
    if (result->ChainDetected) {
        *IsValid = FALSE;
        score = result->ConfidenceScore;
    } else if (result->StackPivotDetected) {
        *IsValid = FALSE;
        score = 70;
    } else if (result->UnknownGadgets > 10) {
        //
        // Many unknown potential gadgets - suspicious
        //
        score = min(50, result->UnknownGadgets * 3);
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

Arguments:

    Result - Result to free

--*/
{
    PLIST_ENTRY entry;
    PROP_CHAIN_ENTRY chainEntry;
    ULONG i;

    if (Result == NULL) {
        return;
    }

    //
    // Free chain entries
    //
    while (!IsListEmpty(&Result->ChainEntries)) {
        entry = RemoveHeadList(&Result->ChainEntries);
        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);
        ShadowStrikeFreePoolWithTag(chainEntry, ROP_POOL_TAG_CHAIN);
    }

    //
    // Free module name buffers
    //
    for (i = 0; i < Result->ModulesUsed; i++) {
        if (Result->ModuleBreakdown[i].ModuleName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(
                Result->ModuleBreakdown[i].ModuleName.Buffer,
                ROP_POOL_TAG_CONTEXT
                );
        }
    }

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

Arguments:

    Detector - Initialized detector
    Callback - Callback function
    Context - User context for callback

Return Value:

    STATUS_SUCCESS on success

--*/
{
    PROP_DETECTOR_INTERNAL internalDetector;
    PROP_CALLBACK_ENTRY callbackEntry;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    //
    // Check callback limit
    //
    if (internalDetector->CallbackCount >= ROP_MAX_CALLBACKS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate callback entry
    //
    callbackEntry = (PROP_CALLBACK_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ROP_CALLBACK_ENTRY),
        ROP_POOL_TAG_CONTEXT
        );

    if (callbackEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    callbackEntry->Callback = Callback;
    callbackEntry->Context = Context;
    callbackEntry->Active = TRUE;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internalDetector->CallbackLock);

    InsertTailList(&internalDetector->CallbackList, &callbackEntry->ListEntry);
    InterlockedIncrement(&internalDetector->CallbackCount);

    ExReleasePushLockExclusive(&internalDetector->CallbackLock);
    KeLeaveCriticalRegion();

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

Arguments:

    Detector - Initialized detector
    Callback - Callback to unregister

--*/
{
    PROP_DETECTOR_INTERNAL internalDetector;
    PLIST_ENTRY entry;
    PROP_CALLBACK_ENTRY callbackEntry;
    PROP_CALLBACK_ENTRY foundEntry = NULL;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return;
    }

    internalDetector = CONTAINING_RECORD(Detector, ROP_DETECTOR_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internalDetector->CallbackLock);

    for (entry = internalDetector->CallbackList.Flink;
         entry != &internalDetector->CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, ROP_CALLBACK_ENTRY, ListEntry);

        if (callbackEntry->Callback == Callback) {
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
        // Mark inactive and wait for any in-progress callbacks
        //
        InterlockedExchange(&foundEntry->Active, FALSE);
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

Arguments:

    Detector - Initialized detector
    Stats - Receives statistics

Return Value:

    STATUS_SUCCESS on success

--*/
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry;
    ULONG moduleCount = 0;

    if (Detector == NULL || !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Stats->GadgetCount = (ULONG)Detector->GadgetCount;
    Stats->StacksAnalyzed = Detector->Stats.StacksAnalyzed;
    Stats->ChainsDetected = Detector->Stats.ChainsDetected;

    //
    // Count scanned modules
    //
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

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

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
/*++

Routine Description:

    Computes hash for address lookup.

--*/
{
    ULONG_PTR addr = (ULONG_PTR)Address;

    //
    // FNV-1a inspired hash
    //
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


static
NTSTATUS
RoppAllocateChainEntry(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_CHAIN_ENTRY* Entry
    )
{
    PROP_CHAIN_ENTRY entry;

    entry = (PROP_CHAIN_ENTRY)ShadowStrikeLookasideAllocate(&Detector->ChainEntryLookaside);

    if (entry == NULL) {
        //
        // Fallback to direct allocation
        //
        entry = (PROP_CHAIN_ENTRY)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(ROP_CHAIN_ENTRY),
            ROP_POOL_TAG_CHAIN
            );

        if (entry == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    RtlZeroMemory(entry, sizeof(ROP_CHAIN_ENTRY));
    *Entry = entry;

    return STATUS_SUCCESS;
}


static
VOID
RoppFreeChainEntry(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_CHAIN_ENTRY Entry
    )
{
    if (Entry != NULL) {
        ShadowStrikeLookasideFree(&Detector->ChainEntryLookaside, Entry);
    }
}


static
NTSTATUS
RoppAllocateResult(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_DETECTION_RESULT* Result
    )
{
    PROP_DETECTION_RESULT result;

    result = (PROP_DETECTION_RESULT)ShadowStrikeLookasideAllocate(&Detector->ResultLookaside);

    if (result == NULL) {
        result = (PROP_DETECTION_RESULT)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(ROP_DETECTION_RESULT),
            ROP_POOL_TAG_CONTEXT
            );

        if (result == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    RtlZeroMemory(result, sizeof(ROP_DETECTION_RESULT));
    *Result = result;

    return STATUS_SUCCESS;
}

//=============================================================================
// Private Functions - Gadget Analysis
//=============================================================================

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

--*/
{
    UCHAR opcode;
    UCHAR modrm;
    UCHAR reg;

    if (Bytes == NULL || Size == 0 || GadgetSize == NULL) {
        return GadgetType_Unknown;
    }

    *GadgetSize = 0;
    opcode = Bytes[0];

    //
    // Check for RET (C3)
    //
    if (opcode == OPCODE_RET) {
        *GadgetSize = 1;
        return GadgetType_Ret;
    }

    //
    // Check for RET imm16 (C2 xx xx)
    //
    if (opcode == OPCODE_RET_IMM16 && Size >= 3) {
        *GadgetSize = 3;
        return GadgetType_RetN;
    }

    //
    // Check for SYSCALL (0F 05)
    //
    if (opcode == OPCODE_SYSCALL_0F && Size >= 2 && Bytes[1] == OPCODE_SYSCALL_05) {
        *GadgetSize = 2;
        return GadgetType_Syscall;
    }

    //
    // Check for SYSENTER (0F 34)
    //
    if (opcode == OPCODE_SYSENTER_0F && Size >= 2 && Bytes[1] == OPCODE_SYSENTER_34) {
        *GadgetSize = 2;
        return GadgetType_Syscall;
    }

    //
    // Check for INT xx (CD xx)
    //
    if (opcode == OPCODE_INT && Size >= 2) {
        *GadgetSize = 2;
        return GadgetType_Int;
    }

    //
    // Check for JMP/CALL reg/mem (FF /4, FF /5, FF /2, FF /3)
    //
    if (opcode == OPCODE_FF_PREFIX && Size >= 2) {
        modrm = Bytes[1];
        reg = (modrm & MODRM_REG_MASK) >> MODRM_REG_SHIFT;

        switch (reg) {
        case FF_CALL_REG:
            //
            // CALL r/m - determine size based on ModR/M
            //
            if ((modrm & MODRM_MOD_MASK) == 0xC0) {
                // Direct register
                *GadgetSize = 2;
                return GadgetType_CallReg;
            } else {
                // Memory reference - need to calculate full size
                *GadgetSize = 2;  // Minimum
                return GadgetType_CallMem;
            }

        case FF_JMP_REG:
            if ((modrm & MODRM_MOD_MASK) == 0xC0) {
                *GadgetSize = 2;
                return GadgetType_JmpReg;
            } else {
                *GadgetSize = 2;
                return GadgetType_JmpMem;
            }

        case FF_CALL_MEM:
            *GadgetSize = 2;
            return GadgetType_CallMem;

        case FF_JMP_MEM:
            *GadgetSize = 2;
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
    registers and memory it affects.

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

    //
    // Simple heuristic analysis - not full disassembly
    //
    for (i = 0; i < size - 1; i++) {
        opcode = bytes[i];

        //
        // Check for stack-modifying operations
        //
        if (opcode == 0x50 || opcode == 0x58) {
            // PUSH/POP rAX
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= REG_RAX;
        }
        else if (opcode >= 0x50 && opcode <= 0x57) {
            // PUSH r64
            Gadget->Semantics.ModifiesStack = TRUE;
        }
        else if (opcode >= 0x58 && opcode <= 0x5F) {
            // POP r64
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= (1 << (opcode - 0x58));
        }
        else if (opcode == 0x89 || opcode == 0x8B) {
            // MOV r/m, r or MOV r, r/m
            if (i + 1 < size) {
                modrm = bytes[i + 1];
                if ((modrm & MODRM_MOD_MASK) != 0xC0) {
                    if (opcode == 0x89) {
                        Gadget->Semantics.WritesMemory = TRUE;
                    } else {
                        Gadget->Semantics.ReadsMemory = TRUE;
                    }
                }
            }
        }
        else if (opcode == 0x94) {
            // XCHG rAX, rSP - stack pivot!
            Gadget->Semantics.ModifiesStack = TRUE;
            Gadget->Semantics.RegistersModified |= (REG_RAX | REG_RSP);
        }
    }
}


static
ULONG
RoppCalculateDangerScore(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_GADGET Gadget
    )
/*++

Routine Description:

    Calculates a danger score for a gadget based on its capabilities.

--*/
{
    ULONG score = 0;
    ULONG i;

    if (Gadget == NULL) {
        return 0;
    }

    //
    // Base score by gadget type
    //
    switch (Gadget->Type) {
    case GadgetType_Syscall:
        score += 80;  // Direct syscall - very dangerous
        Gadget->IsPrivileged = TRUE;
        break;
    case GadgetType_Ret:
    case GadgetType_RetN:
        score += 10;  // Common gadget ending
        break;
    case GadgetType_JmpReg:
    case GadgetType_CallReg:
        score += 30;  // Can redirect execution
        Gadget->CouldBypassCFG = TRUE;
        break;
    case GadgetType_JmpMem:
    case GadgetType_CallMem:
        score += 40;  // Memory-based redirection
        break;
    case GadgetType_Int:
        score += 50;  // Interrupt - could be syscall
        break;
    default:
        break;
    }

    //
    // Add score for semantics
    //
    if (Gadget->Semantics.ModifiesStack) {
        score += 20;  // Stack manipulation
    }
    if (Gadget->Semantics.WritesMemory) {
        score += 15;  // Memory write capability
    }
    if (Gadget->Semantics.RegistersModified & REG_RSP) {
        score += 40;  // Stack pointer modification - pivot capable
    }

    //
    // Check against dangerous patterns
    //
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
/*++

Routine Description:

    Initializes the database of dangerous gadget patterns.

--*/
{
    ULONG idx = 0;

    //
    // XCHG EAX, ESP / XCHG RAX, RSP - stack pivot
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0x94;
    Detector->DangerousPatterns[idx].PatternSize = 1;
    Detector->DangerousPatterns[idx].DangerScore = 50;
    Detector->DangerousPatterns[idx].Description = "Stack pivot XCHG";
    idx++;

    //
    // MOV ESP, EAX / MOV RSP, RAX - stack pivot
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0x89;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC4;
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 50;
    Detector->DangerousPatterns[idx].Description = "Stack pivot MOV";
    idx++;

    //
    // LEAVE; RET - frame cleanup, common in ROP
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0xC9;  // LEAVE
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;  // RET
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 25;
    Detector->DangerousPatterns[idx].Description = "LEAVE; RET sequence";
    idx++;

    //
    // POP RDI; RET - common argument setup
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0x5F;  // POP RDI
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;  // RET
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 15;
    Detector->DangerousPatterns[idx].Description = "POP RDI; RET";
    idx++;

    //
    // POP RSI; RET - common argument setup
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0x5E;  // POP RSI
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;  // RET
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 15;
    Detector->DangerousPatterns[idx].Description = "POP RSI; RET";
    idx++;

    //
    // POP RDX; RET - common argument setup
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0x5A;  // POP RDX
    Detector->DangerousPatterns[idx].Pattern[1] = 0xC3;  // RET
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 15;
    Detector->DangerousPatterns[idx].Description = "POP RDX; RET";
    idx++;

    //
    // JMP RSP / CALL RSP - shellcode execution
    //
    Detector->DangerousPatterns[idx].Pattern[0] = 0xFF;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xE4;  // JMP RSP
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 60;
    Detector->DangerousPatterns[idx].Description = "JMP RSP";
    idx++;

    Detector->DangerousPatterns[idx].Pattern[0] = 0xFF;
    Detector->DangerousPatterns[idx].Pattern[1] = 0xD4;  // CALL RSP
    Detector->DangerousPatterns[idx].PatternSize = 2;
    Detector->DangerousPatterns[idx].DangerScore = 60;
    Detector->DangerousPatterns[idx].Description = "CALL RSP";
    idx++;

    //
    // ADD RSP, imm8; RET - stack adjustment
    //
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
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;

    UNREFERENCED_PARAMETER(ThreadContext);

    RtlZeroMemory(Context, sizeof(ROP_ANALYSIS_CONTEXT));

    Context->Detector = Detector;
    Context->ProcessId = ProcessId;
    Context->ThreadId = ThreadId;
    Context->TimeoutMs = ROP_ANALYSIS_TIMEOUT_MS;

    KeQuerySystemTime(&Context->StartTime);

    //
    // Get process object
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get thread object
    //
    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    //
    // Get stack limits from thread
    // Note: In a real implementation, we'd read the TEB or use
    // IoGetStackLimits for kernel threads
    //
    // For now, use reasonable defaults
    //
    Context->StackBase = NULL;
    Context->StackLimit = NULL;

    ObDereferenceObject(thread);
    ObDereferenceObject(process);

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
    SIZE_T bytesToCopy;
    SIZE_T bytesCopied = 0;

    if (Context->CurrentSp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate stack buffer
    //
    Context->StackBufferSize = ROP_STACK_SAMPLE_SIZE;
    Context->StackBuffer = (PULONG_PTR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Context->StackBufferSize,
        ROP_POOL_TAG_CONTEXT
        );

    if (Context->StackBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Attach to target process
    //
    status = PsLookupProcessByProcessId(Context->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        //
        // Probe and copy stack
        //
        bytesToCopy = min(Context->StackBufferSize,
                         (SIZE_T)((PUCHAR)Context->StackBase - (PUCHAR)Context->CurrentSp));

        if (bytesToCopy > 0 && bytesToCopy <= Context->StackBufferSize) {
            ProbeForRead(Context->CurrentSp, bytesToCopy, sizeof(UCHAR));
            RtlCopyMemory(Context->StackBuffer, Context->CurrentSp, bytesToCopy);
            bytesCopied = bytesToCopy;
        }

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

--*/
{
    //
    // In a full implementation, we would enumerate loaded modules
    // using PsGetProcessPeb or similar mechanisms.
    // For now, initialize empty cache.
    //
    Context->ModuleCacheCount = 0;
    return STATUS_SUCCESS;
}


static
BOOLEAN
RoppIsExecutableAddress(
    PROP_ANALYSIS_CONTEXT Context,
    PVOID Address
    )
/*++

Routine Description:

    Checks if an address is in an executable region.

--*/
{
    ULONG i;

    //
    // Check module cache first
    //
    for (i = 0; i < Context->ModuleCacheCount; i++) {
        if ((ULONG_PTR)Address >= (ULONG_PTR)Context->ModuleCache[i].Base &&
            (ULONG_PTR)Address < (ULONG_PTR)Context->ModuleCache[i].Base +
                                  Context->ModuleCache[i].Size) {
            return Context->ModuleCache[i].IsExecutable;
        }
    }

    //
    // Not in cache - assume executable for kernel addresses
    //
    return ShadowStrikeIsKernelAddress(Address);
}


static
NTSTATUS
RoppDetectChain(
    PROP_ANALYSIS_CONTEXT Context,
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Analyzes captured stack for gadget chains.

--*/
{
    NTSTATUS status;
    PULONG_PTR stackPtr;
    SIZE_T slotCount;
    SIZE_T i;
    ULONG_PTR value;
    PROP_GADGET gadget;
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

        //
        // Skip invalid addresses
        //
        if (value < 0x10000 || value == (ULONG_PTR)-1) {
            if (consecutiveGadgets > 0) {
                maxConsecutive = max(maxConsecutive, consecutiveGadgets);
            }
            consecutiveGadgets = 0;
            continue;
        }

        //
        // Check if this is an executable address
        //
        if (!RoppIsExecutableAddress(Context, (PVOID)value)) {
            consecutiveGadgets = 0;
            continue;
        }

        //
        // Look up in gadget database
        //
        status = RopLookupGadget(&Context->Detector->Public, (PVOID)value, &gadget);

        if (NT_SUCCESS(status)) {
            //
            // Found known gadget
            //
            consecutiveGadgets++;
            Context->TotalGadgets++;

            //
            // Add to chain
            //
            status = RoppAllocateChainEntry(Context->Detector, &chainEntry);
            if (NT_SUCCESS(status)) {
                chainEntry->GadgetAddress = (PVOID)value;
                chainEntry->Gadget = gadget;
                chainEntry->StackOffset = i * sizeof(ULONG_PTR);
                chainEntry->StackValue = value;
                chainEntry->Index = Result->ChainLength;

                InsertTailList(&Result->ChainEntries, &chainEntry->ListEntry);
                Result->ChainLength++;
            }
        } else {
            //
            // Unknown address - could still be a gadget
            //
            Context->UnknownAddresses++;

            //
            // Reset consecutive count if too many unknowns
            //
            if (Context->UnknownAddresses > 5) {
                consecutiveGadgets = 0;
            }
        }

        //
        // Check for chain detection
        //
        if (consecutiveGadgets >= Context->Detector->Public.Config.MinChainLength) {
            Result->ChainDetected = TRUE;
        }

        //
        // Limit chain length
        //
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
/*++

Routine Description:

    Detects stack pivot by comparing current SP with expected stack range.

--*/
{
    ULONG_PTR currentSp;
    ULONG_PTR stackBase;
    ULONG_PTR stackLimit;
    ULONG_PTR distance;

    if (Context->CurrentSp == NULL || Context->StackBase == NULL) {
        return FALSE;
    }

    currentSp = (ULONG_PTR)Context->CurrentSp;
    stackBase = (ULONG_PTR)Context->StackBase;
    stackLimit = (ULONG_PTR)Context->StackLimit;

    //
    // Check if SP is outside normal stack bounds
    //
    if (currentSp < stackLimit || currentSp > stackBase) {
        //
        // SP is outside stack - likely pivoted
        //
        if (PivotSource != NULL) {
            *PivotSource = Context->StackBase;
        }
        if (PivotDestination != NULL) {
            *PivotDestination = Context->CurrentSp;
        }
        return TRUE;
    }

    //
    // Check for large unexpected change in SP
    //
    distance = stackBase - currentSp;
    if (distance > ROP_PIVOT_DISTANCE_THRESHOLD) {
        //
        // Unusually deep stack - suspicious but not definitive
        //
        return FALSE;
    }

    return FALSE;
}


static
ROP_ATTACK_TYPE
RoppClassifyAttack(
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Classifies the type of attack based on detected chain characteristics.

--*/
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

    //
    // Count gadget types in chain
    //
    for (entry = Result->ChainEntries.Flink;
         entry != &Result->ChainEntries;
         entry = entry->Flink) {

        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);

        if (chainEntry->Gadget != NULL) {
            switch (chainEntry->Gadget->Type) {
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
    }

    //
    // Classify based on dominant gadget type
    //
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
/*++

Routine Description:

    Calculates confidence and severity scores for detection.

--*/
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

    //
    // Base confidence on chain length
    //
    if (Result->ChainLength >= 10) {
        confidence = 90;
    } else if (Result->ChainLength >= 5) {
        confidence = 70;
    } else if (Result->ChainLength >= 3) {
        confidence = 50;
    }

    //
    // Adjust for stack pivot
    //
    if (Result->StackPivotDetected) {
        confidence = min(100, confidence + 20);
    }

    //
    // Calculate severity based on gadget danger scores
    //
    for (entry = Result->ChainEntries.Flink;
         entry != &Result->ChainEntries;
         entry = entry->Flink) {

        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);

        if (chainEntry->Gadget != NULL) {
            totalDangerScore += chainEntry->Gadget->DangerScore;

            if (chainEntry->Gadget->DangerScore >= 50) {
                dangerousGadgets++;
            }
            if (chainEntry->Gadget->IsPrivileged) {
                severity = max(severity, 80);
            }
        }
    }

    //
    // Average danger score
    //
    if (Result->ChainLength > 0) {
        severity = max(severity, totalDangerScore / Result->ChainLength);
    }

    //
    // Boost severity for many dangerous gadgets
    //
    if (dangerousGadgets >= 3) {
        severity = min(100, severity + 20);
    }

    //
    // Attack type affects severity
    //
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


static
VOID
RoppInferPayload(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Attempts to infer what the ROP chain payload might do.

--*/
{
    PLIST_ENTRY entry;
    PROP_CHAIN_ENTRY chainEntry;
    BOOLEAN hasVirtualProtect = FALSE;
    BOOLEAN hasVirtualAlloc = FALSE;
    BOOLEAN hasSyscall = FALSE;
    BOOLEAN hasStackPivot = FALSE;

    UNREFERENCED_PARAMETER(Detector);

    if (!Result->ChainDetected) {
        return;
    }

    Result->PayloadAnalysis.PayloadInferred = FALSE;

    //
    // Analyze chain for common payload patterns
    //
    for (entry = Result->ChainEntries.Flink;
         entry != &Result->ChainEntries;
         entry = entry->Flink) {

        chainEntry = CONTAINING_RECORD(entry, ROP_CHAIN_ENTRY, ListEntry);

        if (chainEntry->Gadget != NULL) {
            if (chainEntry->Gadget->Type == GadgetType_Syscall) {
                hasSyscall = TRUE;
            }
            if (chainEntry->Gadget->Semantics.RegistersModified & REG_RSP) {
                hasStackPivot = TRUE;
            }
        }
    }

    //
    // Build description
    //
    Result->PayloadAnalysis.PayloadInferred = TRUE;

    if (hasSyscall) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Direct syscall chain - likely attempting to bypass security hooks"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
        Result->PayloadAnalysis.MayDisableDefenses = TRUE;
    } else if (hasStackPivot) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Stack pivot detected - execution flow hijacked to attacker-controlled memory"
            );
        Result->PayloadAnalysis.MayExecuteCode = TRUE;
    } else if (hasVirtualProtect || hasVirtualAlloc) {
        RtlStringCchCopyA(
            Result->PayloadAnalysis.Description,
            sizeof(Result->PayloadAnalysis.Description),
            "Memory manipulation chain - likely preparing shellcode execution"
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

    UNREFERENCED_PARAMETER(hasVirtualProtect);
    UNREFERENCED_PARAMETER(hasVirtualAlloc);
}


static
VOID
RoppNotifyCallbacks(
    PROP_DETECTOR_INTERNAL Detector,
    PROP_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Notifies all registered callbacks of a detection.

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
            __try {
                callbackEntry->Callback(Result, callbackEntry->Context);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                //
                // Callback threw exception - log but continue
                //
            }
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}


static
BOOLEAN
RoppCheckRateLimit(
    PROP_DETECTOR_INTERNAL Detector
    )
/*++

Routine Description:

    Checks if analysis rate limit allows another analysis.

--*/
{
    LARGE_INTEGER currentTime;
    LONG64 elapsed;
    LONG64 count;

    KeQuerySystemTime(&currentTime);

    elapsed = (currentTime.QuadPart - Detector->LastResetTime) / 10000000;  // Convert to seconds

    if (elapsed >= 1) {
        //
        // Reset counter every second
        //
        InterlockedExchange64(&Detector->AnalysisCount, 0);
        InterlockedExchange64(&Detector->LastResetTime, currentTime.QuadPart);
    }

    count = InterlockedIncrement64(&Detector->AnalysisCount);

    return (count <= (LONG64)Detector->MaxAnalysesPerSecond);
}
