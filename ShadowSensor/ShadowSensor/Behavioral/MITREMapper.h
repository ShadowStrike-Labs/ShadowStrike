/*++
    ShadowStrike Next-Generation Antivirus
    Module: MITREMapper.h - MITRE ATT&CK mapping
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../Shared/AttackPatterns.h"

#define MM_POOL_TAG 'PAMM'

typedef struct _MM_TACTIC {
    CHAR Id[16];                        // TA00XX
    CHAR Name[64];
    CHAR Description[256];
    ULONG TechniqueCount;
    LIST_ENTRY TechniqueList;
    LIST_ENTRY ListEntry;
} MM_TACTIC, *PMM_TACTIC;

typedef struct _MM_TECHNIQUE {
    MITRE_TECHNIQUE Id;                 // T1XXX
    CHAR StringId[16];
    CHAR Name[128];
    CHAR Description[512];
    
    // Parent tactic
    PMM_TACTIC Tactic;
    
    // Sub-techniques
    BOOLEAN IsSubTechnique;
    MITRE_TECHNIQUE ParentTechnique;
    LIST_ENTRY SubTechniqueList;
    
    // Detection
    ULONG DetectionScore;               // How confident we are in detecting this
    BOOLEAN CanBeDetected;
    CHAR DetectionNotes[256];
    
    // Behavioral indicators
    LIST_ENTRY IndicatorList;
    
    LIST_ENTRY ListEntry;
    LIST_ENTRY SubListEntry;
} MM_TECHNIQUE, *PMM_TECHNIQUE;

typedef struct _MM_BEHAVIORAL_INDICATOR {
    CHAR IndicatorType[32];             // Process, File, Registry, Network, etc.
    CHAR Pattern[256];
    BOOLEAN IsRequired;
    LIST_ENTRY ListEntry;
} MM_BEHAVIORAL_INDICATOR, *PMM_BEHAVIORAL_INDICATOR;

typedef struct _MM_DETECTION {
    PMM_TECHNIQUE Technique;
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    
    // Indicators matched
    ULONG IndicatorsMatched;
    ULONG IndicatorsRequired;
    
    // Confidence
    ULONG ConfidenceScore;              // 0-100
    
    LARGE_INTEGER DetectionTime;
    LIST_ENTRY ListEntry;
} MM_DETECTION, *PMM_DETECTION;

typedef struct _MM_MAPPER {
    BOOLEAN Initialized;
    
    // Tactics
    LIST_ENTRY TacticList;
    ULONG TacticCount;
    
    // All techniques (flat)
    LIST_ENTRY TechniqueList;
    EX_PUSH_LOCK TechniqueLock;
    ULONG TechniqueCount;
    
    // Detections
    LIST_ENTRY DetectionList;
    KSPIN_LOCK DetectionLock;
    volatile LONG DetectionCount;
    
    struct {
        volatile LONG64 TechniquesLoaded;
        volatile LONG64 DetectionsMade;
        LARGE_INTEGER StartTime;
    } Stats;
} MM_MAPPER, *PMM_MAPPER;

NTSTATUS MmInitialize(_Out_ PMM_MAPPER* Mapper);
VOID MmShutdown(_Inout_ PMM_MAPPER Mapper);
NTSTATUS MmLoadTechniques(_In_ PMM_MAPPER Mapper);
NTSTATUS MmLookupTechnique(_In_ PMM_MAPPER Mapper, _In_ MITRE_TECHNIQUE Id, _Out_ PMM_TECHNIQUE* Technique);
NTSTATUS MmLookupByName(_In_ PMM_MAPPER Mapper, _In_ PCSTR Name, _Out_ PMM_TECHNIQUE* Technique);
NTSTATUS MmRecordDetection(_In_ PMM_MAPPER Mapper, _In_ MITRE_TECHNIQUE Id, _In_ HANDLE ProcessId, _In_ PUNICODE_STRING ProcessName, _In_ ULONG ConfidenceScore);
NTSTATUS MmGetTechniquesByTactic(_In_ PMM_MAPPER Mapper, _In_ PCSTR TacticId, _Out_writes_to_(Max, *Count) PMM_TECHNIQUE* Techniques, _In_ ULONG Max, _Out_ PULONG Count);
NTSTATUS MmGetRecentDetections(_In_ PMM_MAPPER Mapper, _In_ ULONG MaxAgeSeconds, _Out_writes_to_(Max, *Count) PMM_DETECTION* Detections, _In_ ULONG Max, _Out_ PULONG Count);

#ifdef __cplusplus
}
#endif
