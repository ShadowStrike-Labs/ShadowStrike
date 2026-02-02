/*++
    ShadowStrike Next-Generation Antivirus
    Module: ProcessAnalyzer.h - Deep process analysis
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/BehaviorTypes.h"

#define PA_POOL_TAG 'APAP'

typedef struct _PA_PROCESS_ANALYSIS {
    HANDLE ProcessId;
    UNICODE_STRING ImagePath;
    UNICODE_STRING CommandLine;
    HANDLE ParentId;
    
    // PE Analysis
    struct {
        BOOLEAN IsPE;
        BOOLEAN Is64Bit;
        BOOLEAN IsDotNet;
        BOOLEAN IsPacked;
        BOOLEAN IsSigned;
        ULONG Entropy;
        ULONG Characteristics;
        ULONG Subsystem;
    } PE;
    
    // Security
    struct {
        BOOLEAN HasDEP;
        BOOLEAN HasASLR;
        BOOLEAN HasCFG;
        BOOLEAN HasIntegrityLevel;
        ULONG IntegrityLevel;
    } Security;
    
    // Behavior indicators
    ULONG SuspicionScore;
    ULONG BehaviorFlags;
    
    LIST_ENTRY ListEntry;
} PA_PROCESS_ANALYSIS, *PPA_PROCESS_ANALYSIS;

typedef struct _PA_ANALYZER {
    BOOLEAN Initialized;
    LIST_ENTRY AnalysisList;
    EX_PUSH_LOCK Lock;
    volatile LONG AnalysisCount;
    
    struct {
        volatile LONG64 ProcessesAnalyzed;
        volatile LONG64 SuspiciousFound;
        LARGE_INTEGER StartTime;
    } Stats;
} PA_ANALYZER, *PPA_ANALYZER;

NTSTATUS PaInitialize(_Out_ PPA_ANALYZER* Analyzer);
VOID PaShutdown(_Inout_ PPA_ANALYZER Analyzer);
NTSTATUS PaAnalyzeProcess(_In_ PPA_ANALYZER Analyzer, _In_ HANDLE ProcessId, _Out_ PPA_PROCESS_ANALYSIS* Analysis);
NTSTATUS PaQuickCheck(_In_ PPA_ANALYZER Analyzer, _In_ HANDLE ProcessId, _Out_ PULONG SuspicionScore);
VOID PaFreeAnalysis(_In_ PPA_PROCESS_ANALYSIS Analysis);

#ifdef __cplusplus
}
#endif
