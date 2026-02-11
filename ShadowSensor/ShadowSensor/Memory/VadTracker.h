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

#define VAD_POOL_TAG_ENTRY      'EDAV'  // VAD Tracker - Region Entry
#define VAD_POOL_TAG_TREE       'TDAV'  // VAD Tracker - Tree/Tracker
#define VAD_POOL_TAG_SNAPSHOT   'SDAV'  // VAD Tracker - Snapshot
#define VAD_POOL_TAG_CHANGE     'CDAV'  // VAD Tracker - Change Event
#define VAD_POOL_TAG_CONTEXT    'XDAV'  // VAD Tracker - Process Context
#define VAD_POOL_TAG_HASH       'HDAV'  // VAD Tracker - Hash Chain

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
    // List linkage (sole ownership — no AVL copy)
    //
    LIST_ENTRY ListEntry;
    
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
    
    //
    // VAD regions (sorted linked list for lookup + iteration)
    // Protected by RegionLock (push lock, <= APC_LEVEL)
    //
    LIST_ENTRY RegionList;
    EX_PUSH_LOCK RegionLock;
    volatile LONG RegionCount;
    
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
    // Process list linkage
    //
    LIST_ENTRY ListEntry;
    
    //
    // Hash chain linkage (chained hashing)
    //
    LIST_ENTRY HashEntry;
    
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
    // Initialization state (interlocked access only)
    //
    volatile LONG Initialized;
    
    //
    // Active operation reference count for shutdown drain
    //
    volatile LONG ActiveRefCount;
    
    //
    // Process contexts (protected by ProcessListLock push lock)
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;
    
    //
    // Process lookup hash table (chained — each bucket is a list head)
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
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
    volatile LONG SnapshotTimerActive;
    
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

/**
 * @brief VAD change notification callback.
 *
 * IMPORTANT: The Event pointer is only valid for the duration of the callback.
 * Callbacks MUST NOT store the pointer or access it after returning.
 * Callbacks are invoked at IRQL <= APC_LEVEL outside any lock.
 * They must complete quickly and must not acquire locks that could
 * deadlock with the tracker.
 */
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

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadInitialize(
    _Out_ PVAD_TRACKER* Tracker
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
VadShutdown(
    _Inout_ PVAD_TRACKER Tracker
    );

//=============================================================================
// Public API - Process Management
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadStartTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadStopTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
VadIsTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

//=============================================================================
// Public API - VAD Scanning
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadScanProcess(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG SuspicionScore
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadScanAllProcesses(
    _In_ PVAD_TRACKER Tracker
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
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

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
VadAnalyzeRegion(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVAD_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    );

/**
 * Retrieves copies of suspicious regions above a score threshold.
 * The Regions array receives VALUE COPIES (not pointers to internal state).
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
VadGetSuspiciousRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    );

//=============================================================================
// Public API - Change Notification
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadRegisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
VadUnregisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
VadGetNextChange(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_CHANGE_EVENT Event,
    _In_ ULONG TimeoutMs
    );

//=============================================================================
// Public API - Enumeration
//=============================================================================

/**
 * Enumerates regions matching a filter. Returns VALUE COPIES.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
VadEnumerateRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ VAD_REGION_FILTER Filter,
    _In_opt_ PVOID FilterContext,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION Regions,
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

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
VadGetStatistics(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
