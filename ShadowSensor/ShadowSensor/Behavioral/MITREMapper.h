/*++
    ShadowStrike Next-Generation Antivirus
    Module: MITREMapper.h - MITRE ATT&CK mapping
    Copyright (c) ShadowStrike Team

    ENTERPRISE-GRADE MITRE ATT&CK FRAMEWORK INTEGRATION

    Features:
    - O(1) technique lookup via hash table
    - Reference-counted objects for safe lifetime management
    - Thread-safe operations with proper IRQL annotations
    - Detection recording with temporal tracking

    IRQL Contract:
    - MmInitialize/MmShutdown: PASSIVE_LEVEL only
    - MmLoadTechniques: PASSIVE_LEVEL only
    - MmLookupTechnique/MmLookupByName: <= APC_LEVEL
    - MmRecordDetection: <= DISPATCH_LEVEL
    - MmGetRecentDetections: <= DISPATCH_LEVEL
    - MmReleaseTechnique/MmReleaseDetection: <= DISPATCH_LEVEL
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../Shared/AttackPatterns.h"

//
// Pool tags - consistent naming scheme
//
#define MM_POOL_TAG_MAPPER              'pMMS'  // Mapper structure
#define MM_POOL_TAG_TECHNIQUE           'tMMS'  // Technique entries
#define MM_POOL_TAG_TACTIC              'aMMS'  // Tactic entries
#define MM_POOL_TAG_DETECTION           'dMMS'  // Detection records
#define MM_POOL_TAG_INDICATOR           'iMMS'  // Behavioral indicators
#define MM_POOL_TAG_HASH                'hMMS'  // Hash table buckets
#define MM_POOL_TAG_NAME                'nMMS'  // Process name buffers

//
// Configuration constants
//
#define MM_TECHNIQUE_HASH_BUCKETS       256
#define MM_MAX_DETECTIONS               4096
#define MM_MAX_PROCESS_NAME_LENGTH      520     // MAX_PATH * sizeof(WCHAR) + slack

//
// Forward declarations
//
typedef struct _MM_MAPPER MM_MAPPER, *PMM_MAPPER;
typedef struct _MM_TACTIC MM_TACTIC, *PMM_TACTIC;
typedef struct _MM_TECHNIQUE MM_TECHNIQUE, *PMM_TECHNIQUE;
typedef struct _MM_DETECTION MM_DETECTION, *PMM_DETECTION;

//
// Reference-counted tactic structure
//
typedef struct _MM_TACTIC {
    //
    // Reference count for safe lifetime management
    // Initial count = 1 (held by mapper)
    //
    volatile LONG RefCount;

    //
    // Tactic identification
    //
    CHAR Id[16];                        // TA00XX
    CHAR Name[64];
    CHAR Description[256];

    //
    // Techniques in this tactic
    //
    ULONG TechniqueCount;
    LIST_ENTRY TechniqueList;           // Links MM_TECHNIQUE.TacticListEntry

    //
    // Linkage in mapper's tactic list
    //
    LIST_ENTRY ListEntry;
} MM_TACTIC, *PMM_TACTIC;

//
// Reference-counted technique structure
//
typedef struct _MM_TECHNIQUE {
    //
    // Reference count for safe lifetime management
    // Initial count = 1 (held by mapper)
    // Callers must acquire/release references
    //
    volatile LONG RefCount;

    //
    // Technique identification
    //
    ULONG Id;                           // MITRE_T* constant (not enum for storage)
    CHAR StringId[16];                  // "T1059.001" format
    CHAR Name[128];
    CHAR Description[512];

    //
    // Parent tactic (weak reference - tactic outlives techniques)
    //
    PMM_TACTIC Tactic;

    //
    // Sub-technique hierarchy
    //
    BOOLEAN IsSubTechnique;
    ULONG ParentTechniqueId;            // MITRE_T* of parent (0 if none)
    LIST_ENTRY SubTechniqueList;        // Links sub-techniques

    //
    // Detection metadata
    //
    ULONG DetectionScore;               // How confident we are (0-100)
    BOOLEAN CanBeDetected;
    CHAR DetectionNotes[256];

    //
    // Behavioral indicators
    //
    LIST_ENTRY IndicatorList;

    //
    // Hash table linkage (for O(1) lookup by ID)
    //
    LIST_ENTRY HashEntry;

    //
    // Global technique list linkage
    //
    LIST_ENTRY ListEntry;

    //
    // Tactic's technique list linkage
    //
    LIST_ENTRY TacticListEntry;
} MM_TECHNIQUE, *PMM_TECHNIQUE;

//
// Behavioral indicator (for future extensibility)
//
typedef struct _MM_BEHAVIORAL_INDICATOR {
    CHAR IndicatorType[32];             // Process, File, Registry, Network, etc.
    CHAR Pattern[256];
    BOOLEAN IsRequired;
    LIST_ENTRY ListEntry;
} MM_BEHAVIORAL_INDICATOR, *PMM_BEHAVIORAL_INDICATOR;

//
// Reference-counted detection record
//
typedef struct _MM_DETECTION {
    //
    // Reference count for safe lifetime management
    //
    volatile LONG RefCount;

    //
    // Associated technique (reference held)
    //
    PMM_TECHNIQUE Technique;
    BOOLEAN TechniqueRefHeld;           // TRUE if we hold a reference

    //
    // Process information
    //
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;         // Allocated buffer

    //
    // Detection metrics
    //
    ULONG IndicatorsMatched;
    ULONG IndicatorsRequired;
    ULONG ConfidenceScore;              // 0-100

    //
    // Temporal data
    //
    LARGE_INTEGER DetectionTime;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
} MM_DETECTION, *PMM_DETECTION;

//
// Hash bucket for O(1) technique lookup
//
typedef struct _MM_HASH_BUCKET {
    LIST_ENTRY Head;
} MM_HASH_BUCKET, *PMM_HASH_BUCKET;

//
// Main mapper structure
//
typedef struct _MM_MAPPER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    BOOLEAN TechniquesLoaded;

    //
    // Tactics (protected by TechniqueLock)
    //
    LIST_ENTRY TacticList;
    ULONG TacticCount;

    //
    // Techniques - flat list (protected by TechniqueLock)
    //
    LIST_ENTRY TechniqueList;
    ULONG TechniqueCount;

    //
    // Hash table for O(1) lookup by technique ID
    // Protected by TechniqueLock (shared for reads)
    //
    PMM_HASH_BUCKET HashTable;

    //
    // Push lock for technique/tactic access
    // IRQL: Must be <= APC_LEVEL to acquire
    //
    EX_PUSH_LOCK TechniqueLock;

    //
    // Detections (protected by DetectionLock)
    //
    LIST_ENTRY DetectionList;
    volatile LONG DetectionCount;

    //
    // Spin lock for detection access
    // IRQL: Raises to DISPATCH_LEVEL
    //
    KSPIN_LOCK DetectionLock;

    //
    // Statistics (atomically updated)
    //
    struct {
        volatile LONG64 TechniquesLoaded;
        volatile LONG64 DetectionsMade;
        volatile LONG64 TechniqueLookups;
        volatile LONG64 TechniqueHits;
        volatile LONG64 DetectionsEvicted;
        LARGE_INTEGER StartTime;
    } Stats;
} MM_MAPPER, *PMM_MAPPER;

//
// ============================================================================
// PUBLIC API
// ============================================================================
//

//
// Initialization and shutdown
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmInitialize(
    _Out_ PMM_MAPPER* Mapper
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmShutdown(
    _Inout_ PMM_MAPPER Mapper
    );

//
// Technique database management
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmLoadTechniques(
    _In_ PMM_MAPPER Mapper
    );

//
// Technique lookup - returns referenced pointer
// Caller MUST call MmReleaseTechnique when done
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
MmLookupTechnique(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG TechniqueId,
    _Out_ PMM_TECHNIQUE* Technique
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
MmLookupByName(
    _In_ PMM_MAPPER Mapper,
    _In_ PCSTR Name,
    _Out_ PMM_TECHNIQUE* Technique
    );

//
// Reference management
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReferenceTechnique(
    _In_ PMM_TECHNIQUE Technique
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReleaseTechnique(
    _In_ PMM_TECHNIQUE Technique
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReferenceDetection(
    _In_ PMM_DETECTION Detection
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReleaseDetection(
    _In_ PMM_DETECTION Detection
    );

//
// Detection recording
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MmRecordDetection(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG TechniqueId,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ ULONG ConfidenceScore
    );

//
// Queries
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
MmGetTechniquesByTactic(
    _In_ PMM_MAPPER Mapper,
    _In_ PCSTR TacticId,
    _Out_writes_to_(Max, *Count) PMM_TECHNIQUE* Techniques,
    _In_ ULONG Max,
    _Out_ PULONG Count
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MmGetRecentDetections(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG MaxAgeSeconds,
    _Out_writes_to_(Max, *Count) PMM_DETECTION* Detections,
    _In_ ULONG Max,
    _Out_ PULONG Count
    );

#ifdef __cplusplus
}
#endif
