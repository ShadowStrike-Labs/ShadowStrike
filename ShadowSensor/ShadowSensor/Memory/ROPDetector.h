/*++
    ShadowStrike Next-Generation Antivirus
    Module: ROPDetector.h
    
    Purpose: Return-Oriented Programming (ROP) and Jump-Oriented
             Programming (JOP) attack detection.
             
    Architecture:
    - Stack frame analysis for ROP chains
    - Gadget database for known patterns
    - Call stack validation
    - Control flow integrity checking
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/MemoryTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define ROP_POOL_TAG_GADGET     'GPOR'  // ROP Detector - Gadget
#define ROP_POOL_TAG_CHAIN      'CPOR'  // ROP Detector - Chain
#define ROP_POOL_TAG_CONTEXT    'XPOR'  // ROP Detector - Context

//=============================================================================
// Configuration Constants
//=============================================================================

#define ROP_MAX_CHAIN_LENGTH            1024
#define ROP_MIN_CHAIN_LENGTH            3
#define ROP_GADGET_MAX_SIZE             16
#define ROP_MAX_GADGETS_PER_MODULE      4096
#define ROP_STACK_SAMPLE_SIZE           (4 * 1024)  // 4 KB stack sample

//=============================================================================
// Attack Types
//=============================================================================

typedef enum _ROP_ATTACK_TYPE {
    RopAttack_Unknown = 0,
    RopAttack_ROP,                      // Return-Oriented Programming
    RopAttack_JOP,                      // Jump-Oriented Programming
    RopAttack_COP,                      // Call-Oriented Programming
    RopAttack_SROP,                     // Sigreturn-Oriented Programming
    RopAttack_BROP,                     // Blind ROP
    RopAttack_StackPivot,               // Stack pivot attack
    RopAttack_Mixed,                    // Mixed gadget types
} ROP_ATTACK_TYPE;

//=============================================================================
// Gadget Types
//=============================================================================

typedef enum _ROP_GADGET_TYPE {
    GadgetType_Unknown = 0,
    GadgetType_Ret,                     // Ends with RET
    GadgetType_RetN,                    // Ends with RET N
    GadgetType_JmpReg,                  // Ends with JMP reg
    GadgetType_CallReg,                 // Ends with CALL reg
    GadgetType_JmpMem,                  // Ends with JMP [mem]
    GadgetType_CallMem,                 // Ends with CALL [mem]
    GadgetType_Syscall,                 // Ends with SYSCALL/SYSENTER
    GadgetType_Int,                     // Ends with INT
} ROP_GADGET_TYPE;

//=============================================================================
// Gadget Definition
//=============================================================================

typedef struct _ROP_GADGET {
    //
    // Gadget location
    //
    PVOID Address;
    PVOID ModuleBase;
    ULONG ModuleOffset;
    
    //
    // Gadget properties
    //
    ROP_GADGET_TYPE Type;
    ULONG Size;
    UCHAR Bytes[ROP_GADGET_MAX_SIZE];
    
    //
    // Semantic information
    //
    struct {
        BOOLEAN WritesMemory;
        BOOLEAN ReadsMemory;
        BOOLEAN ModifiesStack;
        BOOLEAN ModifiesFlags;
        ULONG RegistersModified;        // Bit mask
        ULONG RegistersRead;            // Bit mask
    } Semantics;
    
    //
    // Risk assessment
    //
    ULONG DangerScore;                  // 0-100
    BOOLEAN IsPrivileged;
    BOOLEAN CouldBypassCFG;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} ROP_GADGET, *PROP_GADGET;

//=============================================================================
// Chain Entry
//=============================================================================

typedef struct _ROP_CHAIN_ENTRY {
    //
    // Gadget reference
    //
    PVOID GadgetAddress;
    PROP_GADGET Gadget;                 // May be NULL if unknown
    
    //
    // Stack position
    //
    ULONG64 StackOffset;
    ULONG64 StackValue;
    
    //
    // Chain position
    //
    ULONG Index;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} ROP_CHAIN_ENTRY, *PROP_CHAIN_ENTRY;

//=============================================================================
// Detection Result
//=============================================================================

typedef struct _ROP_DETECTION_RESULT {
    //
    // Detection summary
    //
    BOOLEAN ChainDetected;
    ROP_ATTACK_TYPE AttackType;
    ULONG ConfidenceScore;
    ULONG SeverityScore;
    
    //
    // Process context
    //
    HANDLE ProcessId;
    HANDLE ThreadId;
    
    //
    // Stack information
    //
    PVOID StackBase;
    PVOID StackLimit;
    PVOID CurrentSp;
    
    //
    // Chain details
    //
    LIST_ENTRY ChainEntries;
    ULONG ChainLength;
    ULONG UniqueGadgets;
    ULONG UnknownGadgets;
    
    //
    // Pivot detection
    //
    BOOLEAN StackPivotDetected;
    PVOID PivotSource;
    PVOID PivotDestination;
    
    //
    // Module distribution
    //
    struct {
        UNICODE_STRING ModuleName;
        ULONG GadgetCount;
    } ModuleBreakdown[16];
    ULONG ModulesUsed;
    
    //
    // Inferred payload
    //
    struct {
        BOOLEAN PayloadInferred;
        CHAR Description[256];
        BOOLEAN MayExecuteCode;
        BOOLEAN MayDisableDefenses;
        BOOLEAN MayEscalatePrivileges;
    } PayloadAnalysis;
    
} ROP_DETECTION_RESULT, *PROP_DETECTION_RESULT;

//=============================================================================
// ROP Detector
//=============================================================================

typedef struct _ROP_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Gadget database
    //
    LIST_ENTRY GadgetList;
    LIST_ENTRY GadgetHash[1024];
    EX_PUSH_LOCK GadgetLock;
    volatile LONG GadgetCount;
    
    //
    // Module tracking
    //
    LIST_ENTRY ScannedModules;
    EX_PUSH_LOCK ModuleLock;
    
    //
    // Configuration
    //
    struct {
        ULONG MinChainLength;
        ULONG MaxChainLength;
        ULONG ConfidenceThreshold;
        BOOLEAN ScanSystemModules;
        BOOLEAN EnableSemanticAnalysis;
    } Config;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 StacksAnalyzed;
        volatile LONG64 ChainsDetected;
        volatile LONG64 GadgetsIndexed;
        LARGE_INTEGER StartTime;
    } Stats;
    
} ROP_DETECTOR, *PROP_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*ROP_DETECTION_CALLBACK)(
    _In_ PROP_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
RopInitialize(
    _Out_ PROP_DETECTOR* Detector
    );

VOID
RopShutdown(
    _Inout_ PROP_DETECTOR Detector
    );

//=============================================================================
// Public API - Gadget Database
//=============================================================================

NTSTATUS
RopScanModuleForGadgets(
    _In_ PROP_DETECTOR Detector,
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _In_ PUNICODE_STRING ModuleName
    );

NTSTATUS
RopAddGadget(
    _In_ PROP_DETECTOR Detector,
    _In_ PVOID Address,
    _In_ PVOID ModuleBase,
    _In_reads_bytes_(Size) PUCHAR Bytes,
    _In_ ULONG Size,
    _In_ ROP_GADGET_TYPE Type
    );

NTSTATUS
RopLookupGadget(
    _In_ PROP_DETECTOR Detector,
    _In_ PVOID Address,
    _Out_ PROP_GADGET* Gadget
    );

//=============================================================================
// Public API - Detection
//=============================================================================

NTSTATUS
RopAnalyzeStack(
    _In_ PROP_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PCONTEXT ThreadContext,
    _Out_ PROP_DETECTION_RESULT* Result
    );

NTSTATUS
RopAnalyzeStackBuffer(
    _In_ PROP_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID StackBuffer,
    _In_ SIZE_T Size,
    _In_ PVOID StackBase,
    _Out_ PROP_DETECTION_RESULT* Result
    );

NTSTATUS
RopValidateCallStack(
    _In_ PROP_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsValid,
    _Out_opt_ PULONG SuspicionScore
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
RopFreeResult(
    _In_ PROP_DETECTION_RESULT Result
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
RopRegisterCallback(
    _In_ PROP_DETECTOR Detector,
    _In_ ROP_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
RopUnregisterCallback(
    _In_ PROP_DETECTOR Detector,
    _In_ ROP_DETECTION_CALLBACK Callback
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _ROP_STATISTICS {
    ULONG GadgetCount;
    ULONG ModulesScanned;
    ULONG64 StacksAnalyzed;
    ULONG64 ChainsDetected;
    LARGE_INTEGER UpTime;
} ROP_STATISTICS, *PROP_STATISTICS;

NTSTATUS
RopGetStatistics(
    _In_ PROP_DETECTOR Detector,
    _Out_ PROP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
