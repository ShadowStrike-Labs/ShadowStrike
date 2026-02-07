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
// Section Types
//=============================================================================

typedef enum _SEC_SECTION_TYPE {
    SecType_Unknown = 0,
    SecType_Data,                       // Data section
    SecType_Image,                      // Image section (PE)
    SecType_ImageNoExecute,             // Image without execute
    SecType_PageFile,                   // Pagefile-backed
    SecType_Physical,                   // Physical memory
    SecType_Reserve,                    // Reserved section
    SecType_Commit,                     // Committed section
} SEC_SECTION_TYPE;

//=============================================================================
// Section Flags
//=============================================================================

typedef enum _SEC_FLAGS {
    SecFlag_None                = 0x00000000,
    SecFlag_Image               = 0x00000001,   // SEC_IMAGE
    SecFlag_ImageNoExecute      = 0x00000002,   // SEC_IMAGE_NO_EXECUTE
    SecFlag_Reserve             = 0x00000004,   // SEC_RESERVE
    SecFlag_Commit              = 0x00000008,   // SEC_COMMIT
    SecFlag_NoCache             = 0x00000010,   // SEC_NOCACHE
    SecFlag_WriteCombine        = 0x00000020,   // SEC_WRITECOMBINE
    SecFlag_LargePages          = 0x00000040,   // SEC_LARGE_PAGES
    SecFlag_File                = 0x00000100,   // Backed by file
    SecFlag_PageFile            = 0x00000200,   // Pagefile-backed
    SecFlag_Physical            = 0x00000400,   // Physical memory
    SecFlag_Based               = 0x00000800,   // Based section
    SecFlag_Execute             = 0x00001000,   // Execute permission
    SecFlag_Write               = 0x00002000,   // Write permission
    SecFlag_Read                = 0x00004000,   // Read permission
} SEC_FLAGS;

//=============================================================================
// Section Suspicion Indicators
//=============================================================================

typedef enum _SEC_SUSPICION {
    SecSuspicion_None               = 0x00000000,
    SecSuspicion_Transacted         = 0x00000001,   // Transacted file
    SecSuspicion_Deleted            = 0x00000002,   // Backing file deleted
    SecSuspicion_CrossProcess       = 0x00000004,   // Mapped cross-process
    SecSuspicion_UnusualPath        = 0x00000008,   // Unusual file path
    SecSuspicion_LargeAnonymous     = 0x00000010,   // Large anonymous section
    SecSuspicion_ExecuteAnonymous   = 0x00000020,   // Executable anonymous
    SecSuspicion_HiddenPE           = 0x00000040,   // Contains hidden PE
    SecSuspicion_RemoteMap          = 0x00000080,   // Remotely mapped
    SecSuspicion_SuspiciousName     = 0x00000100,   // Suspicious section name
    SecSuspicion_NoBackingFile      = 0x00000200,   // Image with no file
    SecSuspicion_ModifiedImage      = 0x00000400,   // Image differs from file
    SecSuspicion_OverlayData        = 0x00000800,   // Has overlay data
} SEC_SUSPICION;

//=============================================================================
// Section Map Entry
//=============================================================================

typedef struct _SEC_MAP_ENTRY {
    //
    // Mapping information
    //
    HANDLE ProcessId;                   // Process that mapped
    PVOID ViewBase;                     // Base address in process
    SIZE_T ViewSize;                    // Size of view
    ULONG64 SectionOffset;              // Offset into section
    
    //
    // Permissions
    //
    ULONG Protection;                   // PAGE_* protection
    ULONG AllocationType;               // MEM_* type
    
    //
    // Timing
    //
    LARGE_INTEGER MapTime;
    LARGE_INTEGER UnmapTime;
    BOOLEAN IsMapped;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} SEC_MAP_ENTRY, *PSEC_MAP_ENTRY;

//=============================================================================
// Section Entry
//=============================================================================

typedef struct _SEC_ENTRY {
    //
    // Section identification
    //
    PVOID SectionObject;                // Kernel section object
    HANDLE CreatorProcessId;            // Process that created section
    ULONG SectionId;                    // Internal ID
    
    //
    // Section properties
    //
    SEC_SECTION_TYPE Type;
    SEC_FLAGS Flags;
    LARGE_INTEGER MaximumSize;
    ULONG SectionPageProtection;
    ULONG AllocationAttributes;
    
    //
    // Backing file information
    //
    struct {
        PFILE_OBJECT FileObject;
        UNICODE_STRING FileName;
        ULONG64 FileSize;
        LARGE_INTEGER FileCreationTime;
        BOOLEAN IsTransacted;           // TxF transaction
        BOOLEAN IsDeleted;
        UCHAR FileHash[32];             // SHA-256 of file
        BOOLEAN HashValid;
    } BackingFile;
    
    //
    // PE information (for image sections)
    //
    struct {
        BOOLEAN IsPE;
        USHORT Machine;
        USHORT Characteristics;
        ULONG ImageSize;
        ULONG EntryPoint;
        BOOLEAN IsDotNet;
        BOOLEAN IsSigned;
    } PE;
    
    //
    // Mapping tracking
    //
    LIST_ENTRY MapList;
    KSPIN_LOCK MapListLock;
    volatile LONG MapCount;
    volatile LONG CrossProcessMapCount;
    
    //
    // Suspicion tracking
    //
    SEC_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    
    //
    // Timing
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastMapTime;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} SEC_ENTRY, *PSEC_ENTRY;

//=============================================================================
// Section Tracker
//=============================================================================

typedef struct _SEC_TRACKER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Section list
    //
    LIST_ENTRY SectionList;
    EX_PUSH_LOCK SectionListLock;
    volatile LONG SectionCount;
    
    //
    // Section lookup hash table (by section object)
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
    } SectionHash;
    
    //
    // ID generation
    //
    volatile LONG NextSectionId;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalCreated;
        volatile LONG64 TotalMapped;
        volatile LONG64 TotalUnmapped;
        volatile LONG64 SuspiciousDetections;
        volatile LONG64 CrossProcessMaps;
        volatile LONG64 TransactedDetections;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ULONG MaxSections;
        BOOLEAN TrackAllSections;
        BOOLEAN EnablePEAnalysis;
        BOOLEAN EnableFileHashing;
    } Config;
    
} SEC_TRACKER, *PSEC_TRACKER;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*SEC_CREATE_CALLBACK)(
    _In_ PSEC_ENTRY Section,
    _In_opt_ PVOID Context
    );

typedef VOID (*SEC_MAP_CALLBACK)(
    _In_ PSEC_ENTRY Section,
    _In_ PSEC_MAP_ENTRY Map,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
SecInitialize(
    _Out_ PSEC_TRACKER* Tracker
    );

VOID
SecShutdown(
    _Inout_ PSEC_TRACKER Tracker
    );

//=============================================================================
// Public API - Section Tracking
//=============================================================================

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

NTSTATUS
SecTrackSectionUnmap(
    _In_ PSEC_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID ViewBase
    );

NTSTATUS
SecUntrackSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject
    );

//=============================================================================
// Public API - Section Query
//=============================================================================

NTSTATUS
SecGetSectionInfo(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PSEC_ENTRY* Entry
    );

NTSTATUS
SecGetSectionById(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG SectionId,
    _Out_ PSEC_ENTRY* Entry
    );

NTSTATUS
SecFindSectionByFile(
    _In_ PSEC_TRACKER Tracker,
    _In_ PUNICODE_STRING FileName,
    _Out_ PSEC_ENTRY* Entry
    );

//=============================================================================
// Public API - Suspicion Analysis
//=============================================================================

NTSTATUS
SecAnalyzeSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PSEC_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    );

NTSTATUS
SecDetectDoppelganging(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PBOOLEAN IsTransacted,
    _Out_ PBOOLEAN FileDeleted
    );

NTSTATUS
SecGetSuspiciousSections(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxEntries, *EntryCount) PSEC_ENTRY* Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount
    );

//=============================================================================
// Public API - Cross-Process Analysis
//=============================================================================

NTSTATUS
SecGetCrossProcessMaps(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_writes_to_(MaxMaps, *MapCount) PSEC_MAP_ENTRY* Maps,
    _In_ ULONG MaxMaps,
    _Out_ PULONG MapCount
    );

NTSTATUS
SecIsCrossProcessMapped(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PBOOLEAN IsCrossProcess,
    _Out_opt_ PULONG ProcessCount
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
SecRegisterCreateCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_CREATE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

NTSTATUS
SecRegisterMapCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_MAP_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
SecUnregisterCallbacks(
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

NTSTATUS
SecGetStatistics(
    _In_ PSEC_TRACKER Tracker,
    _Out_ PSEC_STATISTICS Stats
    );

//=============================================================================
// Public API - Reference Counting
//=============================================================================

VOID
SecAddRef(
    _In_ PSEC_ENTRY Entry
    );

VOID
SecRelease(
    _In_ PSEC_ENTRY Entry
    );

#ifdef __cplusplus
}
#endif
