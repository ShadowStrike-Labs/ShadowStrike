/*++
    ShadowStrike Next-Generation Antivirus
    Module: SectionTracker.h

    Purpose: Section object tracking for detecting malicious
             section mapping and shared memory abuse.

    Architecture:
    - Track NtCreateSection/NtMapViewOfSection
    - Detect transacted sections (process doppelganging)
    - Monitor cross-process section mapping
    - Identify suspicious section characteristics

    Locking Hierarchy (acquire in this order, never invert):
      1. SEC_TRACKER.SectionLock       (push lock - protects list + hash)
      2. SEC_ENTRY.MapListLock         (push lock - protects per-entry map list)
      3. SEC_TRACKER_INTERNAL.CallbackLock (push lock - protects callback array)

    All locks require KeEnterCriticalRegion before acquisition.
    All public APIs require IRQL <= APC_LEVEL.

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

#define SEC_POOL_TAG_ENTRY      'ECES'  // Section Tracker - Entry
#define SEC_POOL_TAG_MAP        'MCES'  // Section Tracker - Map
#define SEC_POOL_TAG_CONTEXT    'CCES'  // Section Tracker - Context

//=============================================================================
// Configuration Constants
//=============================================================================

#define SEC_MAX_TRACKED_SECTIONS        8192
#define SEC_MAX_MAPS_PER_SECTION        256
#define SEC_SUSPICIOUS_SIZE_THRESHOLD   (100 * 1024 * 1024)  // 100 MB
#define SEC_HASH_BUCKET_COUNT           1024

//=============================================================================
// Opaque handle for callback registration
//=============================================================================

typedef PVOID SEC_CALLBACK_HANDLE;

//=============================================================================
// Section Types
//=============================================================================

typedef enum _SEC_SECTION_TYPE {
    SecType_Unknown = 0,
    SecType_Data,
    SecType_Image,
    SecType_ImageNoExecute,
    SecType_PageFile,
    SecType_Physical,
    SecType_Reserve,
    SecType_Commit,
} SEC_SECTION_TYPE;

//=============================================================================
// Section Flags
//=============================================================================

typedef enum _SEC_FLAGS {
    SecFlag_None                = 0x00000000,
    SecFlag_Image               = 0x00000001,
    SecFlag_ImageNoExecute      = 0x00000002,
    SecFlag_Reserve             = 0x00000004,
    SecFlag_Commit              = 0x00000008,
    SecFlag_NoCache             = 0x00000010,
    SecFlag_WriteCombine        = 0x00000020,
    SecFlag_LargePages          = 0x00000040,
    SecFlag_File                = 0x00000100,
    SecFlag_PageFile            = 0x00000200,
    SecFlag_Physical            = 0x00000400,
    SecFlag_Based               = 0x00000800,
    SecFlag_Execute             = 0x00001000,
    SecFlag_Write               = 0x00002000,
    SecFlag_Read                = 0x00004000,
} SEC_FLAGS;

//=============================================================================
// Section Suspicion Indicators
//=============================================================================

typedef enum _SEC_SUSPICION {
    SecSuspicion_None               = 0x00000000,
    SecSuspicion_Transacted         = 0x00000001,
    SecSuspicion_Deleted            = 0x00000002,
    SecSuspicion_CrossProcess       = 0x00000004,
    SecSuspicion_UnusualPath        = 0x00000008,
    SecSuspicion_LargeAnonymous     = 0x00000010,
    SecSuspicion_ExecuteAnonymous   = 0x00000020,
    SecSuspicion_HiddenPE           = 0x00000040,
    SecSuspicion_RemoteMap          = 0x00000080,
    SecSuspicion_SuspiciousName     = 0x00000100,
    SecSuspicion_NoBackingFile      = 0x00000200,
    SecSuspicion_ModifiedImage      = 0x00000400,
    SecSuspicion_OverlayData        = 0x00000800,
} SEC_SUSPICION;

//=============================================================================
// Section Map Info - Opaque snapshot returned to callers (DESIGN-1 fix)
//=============================================================================

typedef struct _SEC_MAP_INFO {
    HANDLE ProcessId;
    PVOID ViewBase;
    SIZE_T ViewSize;
    ULONG64 SectionOffset;
    ULONG Protection;
    ULONG AllocationType;
    LARGE_INTEGER MapTime;
    LARGE_INTEGER UnmapTime;
    BOOLEAN IsMapped;
} SEC_MAP_INFO, *PSEC_MAP_INFO;

//=============================================================================
// Section Info - Opaque read-only snapshot returned to callers (DESIGN-1 fix)
//=============================================================================

typedef struct _SEC_SECTION_INFO {
    ULONG SectionId;
    HANDLE CreatorProcessId;
    SEC_SECTION_TYPE Type;
    SEC_FLAGS Flags;
    LARGE_INTEGER MaximumSize;

    struct {
        UNICODE_STRING FileName;
        ULONG64 FileSize;
        LARGE_INTEGER FileCreationTime;
        BOOLEAN IsTransacted;
        BOOLEAN IsDeleted;
        UCHAR FileHash[32];
        BOOLEAN HashValid;
    } BackingFile;

    struct {
        BOOLEAN IsPE;
        USHORT Machine;
        USHORT Characteristics;
        ULONG ImageSize;
        ULONG EntryPoint;
        BOOLEAN IsDotNet;
        BOOLEAN IsSigned;
    } PE;

    LONG MapCount;
    LONG CrossProcessMapCount;
    SEC_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastMapTime;
} SEC_SECTION_INFO, *PSEC_SECTION_INFO;

//=============================================================================
// Internal Map Entry (opaque to callers — only used inside .c)
//=============================================================================

typedef struct _SEC_MAP_ENTRY {
    HANDLE ProcessId;
    PVOID ViewBase;
    SIZE_T ViewSize;
    ULONG64 SectionOffset;
    ULONG Protection;
    ULONG AllocationType;
    LARGE_INTEGER MapTime;
    LARGE_INTEGER UnmapTime;
    BOOLEAN IsMapped;
    LIST_ENTRY ListEntry;
} SEC_MAP_ENTRY, *PSEC_MAP_ENTRY;

//=============================================================================
// Internal Section Entry (opaque to callers — only used inside .c)
//=============================================================================

typedef struct _SEC_ENTRY {
    PVOID SectionObject;
    HANDLE CreatorProcessId;
    ULONG SectionId;

    SEC_SECTION_TYPE Type;
    SEC_FLAGS Flags;
    LARGE_INTEGER MaximumSize;
    ULONG SectionPageProtection;
    ULONG AllocationAttributes;

    struct {
        PFILE_OBJECT FileObject;
        UNICODE_STRING FileName;
        ULONG64 FileSize;
        LARGE_INTEGER FileCreationTime;
        BOOLEAN IsTransacted;
        BOOLEAN IsDeleted;
        UCHAR FileHash[32];
        BOOLEAN HashValid;
    } BackingFile;

    struct {
        BOOLEAN IsPE;
        USHORT Machine;
        USHORT Characteristics;
        ULONG ImageSize;
        ULONG EntryPoint;
        BOOLEAN IsDotNet;
        BOOLEAN IsSigned;
    } PE;

    LIST_ENTRY MapList;
    EX_PUSH_LOCK MapListLock;              // Push lock (was spin lock)
    volatile LONG MapCount;
    volatile LONG CrossProcessMapCount;

    volatile LONG SuspicionFlags;          // Atomically updated via InterlockedOr
    volatile LONG SuspicionScore;          // Atomically updated via InterlockedExchange

    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastMapTime;

    volatile LONG RefCount;
    BOOLEAN RemovedFromTracker;

    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

    PSEC_TRACKER Tracker;                  // Back-pointer for ref-counted free
} SEC_ENTRY, *PSEC_ENTRY;

//=============================================================================
// Section Tracker (forward-declared; internal layout in .c)
//=============================================================================

typedef struct _SEC_TRACKER {
    BOOLEAN Initialized;

    LIST_ENTRY SectionList;
    EX_PUSH_LOCK SectionLock;              // Single lock: protects list + hash
    volatile LONG SectionCount;

    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } SectionHash;

    volatile LONG NextSectionId;

    struct {
        volatile LONG64 TotalCreated;
        volatile LONG64 TotalMapped;
        volatile LONG64 TotalUnmapped;
        volatile LONG64 SuspiciousDetections;
        volatile LONG64 CrossProcessMaps;
        volatile LONG64 TransactedDetections;
        LARGE_INTEGER StartTime;
    } Stats;

    struct {
        ULONG MaxSections;
        BOOLEAN TrackAllSections;
        BOOLEAN EnablePEAnalysis;
        BOOLEAN EnableFileHashing;
    } Config;
} SEC_TRACKER, *PSEC_TRACKER;

//=============================================================================
// Callback Types — receive read-only snapshots, not internal pointers
//=============================================================================

typedef VOID (*SEC_CREATE_CALLBACK)(
    _In_ const SEC_SECTION_INFO* SectionInfo,
    _In_opt_ PVOID Context
    );

typedef VOID (*SEC_MAP_CALLBACK)(
    _In_ const SEC_SECTION_INFO* SectionInfo,
    _In_ const SEC_MAP_INFO* MapInfo,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SecInitialize(
    _Out_ PSEC_TRACKER* Tracker
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SecShutdown(
    _Inout_ PSEC_TRACKER Tracker
    );

//=============================================================================
// Public API - Section Tracking
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecTrackSectionCreate(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _In_ HANDLE CreatorProcessId,
    _In_ SEC_FLAGS Flags,
    _In_opt_ PFILE_OBJECT FileObject,
    _In_ PLARGE_INTEGER MaximumSize,
    _Out_opt_ PULONG SectionId
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecTrackSectionMap(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _In_ HANDLE ProcessId,
    _In_ PVOID ViewBase,
    _In_ SIZE_T ViewSize,
    _In_ ULONG64 SectionOffset,
    _In_ ULONG Protection
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecTrackSectionUnmap(
    _In_ PSEC_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID ViewBase
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecUntrackSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject
    );

//=============================================================================
// Public API - Section Query (returns opaque snapshots)
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecGetSectionInfo(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PSEC_SECTION_INFO Info
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecGetSectionById(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG SectionId,
    _Out_ PSEC_SECTION_INFO Info
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecFindSectionByFile(
    _In_ PSEC_TRACKER Tracker,
    _In_ PUNICODE_STRING FileName,
    _Out_ PSEC_SECTION_INFO Info
    );

//=============================================================================
// Public API - Suspicion Analysis
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecAnalyzeSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ SEC_SUSPICION* SuspicionFlags,
    _Out_ PULONG SuspicionScore
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecDetectDoppelganging(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PBOOLEAN IsTransacted,
    _Out_ PBOOLEAN FileDeleted
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecGetSuspiciousSections(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxEntries, *EntryCount) PSEC_SECTION_INFO Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount
    );

//=============================================================================
// Public API - Cross-Process Analysis (returns copied snapshots)
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecGetCrossProcessMaps(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_writes_to_(MaxMaps, *MapCount) PSEC_MAP_INFO Maps,
    _In_ ULONG MaxMaps,
    _Out_ PULONG MapCount
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecIsCrossProcessMapped(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PBOOLEAN IsCrossProcess,
    _Out_opt_ PULONG ProcessCount
    );

//=============================================================================
// Public API - Callbacks (with per-registration handle)
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecRegisterCreateCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_CREATE_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ SEC_CALLBACK_HANDLE* Handle
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecRegisterMapCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_MAP_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ SEC_CALLBACK_HANDLE* Handle
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecUnregisterCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_CALLBACK_HANDLE Handle
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
SecUnregisterAllCallbacks(
    _In_ PSEC_TRACKER Tracker
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _SEC_STATISTICS {
    ULONG ActiveSections;
    ULONG64 TotalCreated;
    ULONG64 TotalMapped;
    ULONG64 TotalUnmapped;
    ULONG64 SuspiciousDetections;
    ULONG64 CrossProcessMaps;
    ULONG64 TransactedDetections;
    LARGE_INTEGER UpTime;
} SEC_STATISTICS, *PSEC_STATISTICS;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SecGetStatistics(
    _In_ PSEC_TRACKER Tracker,
    _Out_ PSEC_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
