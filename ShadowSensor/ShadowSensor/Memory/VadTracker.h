/*++
    ShadowStrike Next-Generation Antivirus
    Module: VadTracker.h
    
    Purpose: Virtual Address Descriptor (VAD) tree monitoring for
             detecting suspicious memory regions and modifications.
             
    Architecture:
    - Track VAD tree changes for all monitored processes
    - Detect unbacked executable regions
    - Identify suspicious memory permissions
    - Monitor memory region growth patterns
    
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

#define VAD_POOL_TAG_ENTRY      'EDAV'  // VAD Tracker - Entry
#define VAD_POOL_TAG_TREE       'TDAV'  // VAD Tracker - Tree
#define VAD_POOL_TAG_SNAPSHOT   'SDAV'  // VAD Tracker - Snapshot

//=============================================================================
// Configuration Constants
//=============================================================================

#define VAD_MAX_TRACKED_PROCESSES       1024
#define VAD_MAX_REGIONS_PER_PROCESS     16384
#define VAD_SNAPSHOT_INTERVAL_MS        5000
#define VAD_CHANGE_BATCH_SIZE           64
#define VAD_SUSPICIOUS_REGION_THRESHOLD 100

//=============================================================================
// VAD Flags (from Windows internals)
//=============================================================================

typedef enum _VAD_FLAGS {
    VadFlag_None                    = 0x00000000,
    VadFlag_Private                 = 0x00000001,   // MEM_PRIVATE
    VadFlag_Mapped                  = 0x00000002,   // MEM_MAPPED
    VadFlag_Image                   = 0x00000004,   // MEM_IMAGE
    VadFlag_Execute                 = 0x00000010,   // PAGE_EXECUTE*
    VadFlag_Write                   = 0x00000020,   // PAGE_*WRITE*
    VadFlag_Read                    = 0x00000040,   // PAGE_*READ*
    VadFlag_Guard                   = 0x00000080,   // PAGE_GUARD
    VadFlag_NoCache                 = 0x00000100,   // PAGE_NOCACHE
    VadFlag_WriteCombine            = 0x00000200,   // PAGE_WRITECOMBINE
    VadFlag_CopyOnWrite             = 0x00000400,   // Copy-on-write
    VadFlag_Commit                  = 0x00000800,   // Committed
    VadFlag_Reserve                 = 0x00001000,   // Reserved only
    VadFlag_Large                   = 0x00002000,   // Large pages
    VadFlag_Physical                = 0x00004000,   // Physical pages mapped
} VAD_FLAGS;

//=============================================================================
// VAD Suspicion Indicators
//=============================================================================

typedef enum _VAD_SUSPICION {
    VadSuspicion_None               = 0x00000000,
    VadSuspicion_RWX                = 0x00000001,   // RWX permissions
    VadSuspicion_UnbackedExecute    = 0x00000002,   // Private + Execute
    VadSuspicion_LargePrivate       = 0x00000004,   // Large private region
    VadSuspicion_GuardRegion        = 0x00000008,   // Guard page pattern
    VadSuspicion_RecentRWtoRX       = 0x00000010,   // RW->RX transition
    VadSuspicion_HiddenRegion       = 0x00000020,   // Region not in VAD
    VadSuspicion_ProtectionMismatch = 0x00000040,   // PTE != VAD protection
    VadSuspicion_SuspiciousBase     = 0x00000080,   // Unusual base address
    VadSuspicion_OverlapWithImage   = 0x00000100,   // Overlaps loaded image
    VadSuspicion_ShellcodePattern   = 0x00000200,   // Contains shellcode
} VAD_SUSPICION;

//=============================================================================
// VAD Region Entry
//=============================================================================

typedef struct _VAD_REGION {
    //
    // Region bounds
    //
    PVOID BaseAddress;
    SIZE_T RegionSize;
    
    //
    // Permissions
    //
    VAD_FLAGS CurrentFlags;
    VAD_FLAGS OriginalFlags;
    ULONG Protection;                   // PAGE_* constants
    ULONG OriginalProtection;
    
    //
    // Region type
    //
    ULONG Type;                         // MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE
    ULONG State;                        // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    
    //
    // Backing information
    //
    PVOID FileObject;                   // Backing file (if any)
    UNICODE_STRING FileName;            // Backing file name
    ULONG64 FileOffset;                 // Offset in file
    BOOLEAN IsBacked;
    
    //
    // Suspicion tracking
    //
    VAD_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    ULONG ProtectionChangeCount;
    
    //
    // Timing
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastModifyTime;
    LARGE_INTEGER LastAccessTime;
    
    //
    // Analysis results
    //
    BOOLEAN Analyzed;
    BOOLEAN ContainsCode;
    BOOLEAN ContainsShellcode;
    ULONG Entropy;                      // 0-100 scale
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    RTL_BALANCED_NODE TreeNode;         // For AVL tree
    
} VAD_REGION, *PVAD_REGION;

//=============================================================================
// Process VAD Context
//=============================================================================

typedef struct _VAD_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    PEPROCESS Process;
    UNICODE_STRING ImageName;
    
    //
    // VAD regions (AVL tree for fast lookup)
    //
    RTL_AVL_TABLE RegionTree;
    KSPIN_LOCK TreeLock;
    volatile LONG RegionCount;
    
    //
    // Region list (for iteration)
    //
    LIST_ENTRY RegionList;
    
    //
    // Suspicion tracking
    //
    ULONG TotalSuspicionScore;
    ULONG SuspiciousRegionCount;
    ULONG RWXRegionCount;
    ULONG UnbackedExecuteCount;
    
    //
    // Memory statistics
    //
    SIZE_T TotalPrivateSize;
    SIZE_T TotalMappedSize;
    SIZE_T TotalImageSize;
    SIZE_T TotalExecutableSize;
    
    //
    // Snapshot for change detection
    //
    struct {
        PVOID SnapshotBuffer;
        ULONG SnapshotSize;
        LARGE_INTEGER SnapshotTime;
        BOOLEAN Valid;
    } Snapshot;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} VAD_PROCESS_CONTEXT, *PVAD_PROCESS_CONTEXT;

//=============================================================================
// VAD Change Event
//=============================================================================

typedef enum _VAD_CHANGE_TYPE {
    VadChange_RegionCreated = 1,
    VadChange_RegionDeleted,
    VadChange_ProtectionChanged,
    VadChange_RegionGrew,
    VadChange_RegionShrunk,
    VadChange_Committed,
    VadChange_Decommitted,
} VAD_CHANGE_TYPE;

typedef struct _VAD_CHANGE_EVENT {
    //
    // Change information
    //
    VAD_CHANGE_TYPE ChangeType;
    HANDLE ProcessId;
    
    //
    // Region details
    //
    PVOID BaseAddress;
    SIZE_T RegionSize;
    VAD_FLAGS OldFlags;
    VAD_FLAGS NewFlags;
    ULONG OldProtection;
    ULONG NewProtection;
    
    //
    // Suspicion
    //
    VAD_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    
    //
    // Timing
    //
    LARGE_INTEGER Timestamp;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} VAD_CHANGE_EVENT, *PVAD_CHANGE_EVENT;

//=============================================================================
// VAD Tracker
//=============================================================================

typedef struct _VAD_TRACKER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Process contexts
    //
    LIST_ENTRY ProcessList;
    KSPIN_LOCK ProcessListLock;
    volatile LONG ProcessCount;
    
    //
    // Process lookup hash table
    //
    struct {
        PVAD_PROCESS_CONTEXT* Buckets;
        ULONG BucketCount;
        KSPIN_LOCK Lock;
    } ProcessHash;
    
    //
    // Change event queue
    //
    LIST_ENTRY ChangeQueue;
    KSPIN_LOCK ChangeQueueLock;
    volatile LONG ChangeCount;
    KEVENT ChangeAvailableEvent;
    
    //
    // Snapshot timer
    //
    KTIMER SnapshotTimer;
    KDPC SnapshotDpc;
    BOOLEAN SnapshotTimerActive;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalScans;
        volatile LONG64 SuspiciousRegions;
        volatile LONG64 ProtectionChanges;
        volatile LONG64 RWXDetections;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ULONG SnapshotIntervalMs;
        ULONG MaxTrackedProcesses;
        ULONG MaxRegionsPerProcess;
        BOOLEAN TrackAllProcesses;
        BOOLEAN EnableChangeNotification;
    } Config;
    
} VAD_TRACKER, *PVAD_TRACKER;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*VAD_CHANGE_CALLBACK)(
    _In_ PVAD_CHANGE_EVENT Event,
    _In_opt_ PVOID Context
    );

typedef BOOLEAN (*VAD_REGION_FILTER)(
    _In_ PVAD_REGION Region,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
VadInitialize(
    _Out_ PVAD_TRACKER* Tracker
    );

VOID
VadShutdown(
    _Inout_ PVAD_TRACKER Tracker
    );

//=============================================================================
// Public API - Process Management
//=============================================================================

NTSTATUS
VadStartTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

NTSTATUS
VadStopTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

BOOLEAN
VadIsTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

//=============================================================================
// Public API - VAD Scanning
//=============================================================================

NTSTATUS
VadScanProcess(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG SuspicionScore
    );

NTSTATUS
VadScanAllProcesses(
    _In_ PVAD_TRACKER Tracker
    );

NTSTATUS
VadGetRegionInfo(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVAD_REGION RegionInfo
    );

//=============================================================================
// Public API - Suspicion Analysis
//=============================================================================

NTSTATUS
VadAnalyzeRegion(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVAD_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    );

NTSTATUS
VadGetSuspiciousRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION* Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    );

//=============================================================================
// Public API - Change Notification
//=============================================================================

NTSTATUS
VadRegisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
VadUnregisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback
    );

NTSTATUS
VadGetNextChange(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_CHANGE_EVENT Event,
    _In_ ULONG TimeoutMs
    );

//=============================================================================
// Public API - Enumeration
//=============================================================================

NTSTATUS
VadEnumerateRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ VAD_REGION_FILTER Filter,
    _In_opt_ PVOID FilterContext,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION* Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _VAD_STATISTICS {
    ULONG TrackedProcesses;
    ULONG64 TotalRegions;
    ULONG64 TotalScans;
    ULONG64 SuspiciousDetections;
    ULONG64 RWXDetections;
    ULONG64 ProtectionChanges;
    LARGE_INTEGER UpTime;
} VAD_STATISTICS, *PVAD_STATISTICS;

NTSTATUS
VadGetStatistics(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
