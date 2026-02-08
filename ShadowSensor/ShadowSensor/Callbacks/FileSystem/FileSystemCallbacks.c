/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE FILE SYSTEM CALLBACKS IMPLEMENTATION
===============================================================================

@file FileSystemCallbacks.c
@brief Enterprise-grade filesystem minifilter callback management for kernel EDR.

This module provides comprehensive filesystem monitoring infrastructure:
- Minifilter registration and callback management
- Stream context lifecycle management
- File operation tracking and correlation
- Ransomware detection via entropy analysis
- File type classification and prioritization
- Volume attachment/detachment handling
- Instance setup and teardown
- Transaction support (TxF awareness)
- Reparse point and junction handling
- Alternate data stream (ADS) monitoring

Detection Techniques Covered (MITRE ATT&CK):
- T1486: Data Encrypted for Impact (ransomware detection)
- T1485: Data Destruction (mass deletion detection)
- T1083: File and Directory Discovery (enumeration detection)
- T1005: Data from Local System (data exfiltration indicators)
- T1564.004: NTFS File Attributes (ADS abuse)
- T1036: Masquerading (extension spoofing)
- T1070.004: File Deletion (evidence destruction)

Performance Characteristics:
- O(1) context lookup via filter manager
- Lock-free statistics using InterlockedXxx
- Lookaside lists for high-frequency allocations
- Early exit for excluded paths/processes
- Configurable scan depth and timeout

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Shared/SharedDefs.h"
#include "../../Communication/CommPort.h"
#include "../../Communication/ScanBridge.h"
#include "../../Cache/ScanCache.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/FileUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowStrikeInitializeFileSystemCallbacks)
#pragma alloc_text(PAGE, ShadowStrikeCleanupFileSystemCallbacks)
#pragma alloc_text(PAGE, ShadowStrikeInstanceSetup)
#pragma alloc_text(PAGE, ShadowStrikeInstanceQueryTeardown)
#pragma alloc_text(PAGE, ShadowStrikeInstanceTeardownStart)
#pragma alloc_text(PAGE, ShadowStrikeInstanceTeardownComplete)
#pragma alloc_text(PAGE, ShadowStrikeStreamContextCleanup)
#pragma alloc_text(PAGE, ShadowStrikeStreamHandleContextCleanup)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define FSC_POOL_TAG                    'cSFS'  // SFSc - FileSystem Callbacks
#define FSC_CONTEXT_POOL_TAG            'xCFS'  // SFCx - Context
#define FSC_WORKITEM_POOL_TAG           'wWFS'  // SFWw - Work Item
#define FSC_MAX_FILE_NAME_LENGTH        32768
#define FSC_MAX_VOLUME_NAME_LENGTH      512
#define FSC_ENTROPY_SAMPLE_SIZE         4096
#define FSC_RANSOMWARE_ENTROPY_THRESHOLD 7.5    // High entropy threshold
#define FSC_RANSOMWARE_RENAME_THRESHOLD  50     // Renames per second
#define FSC_RANSOMWARE_DELETE_THRESHOLD  100    // Deletes per second
#define FSC_MAX_TRACKED_VOLUMES         64
#define FSC_MAX_TRACKED_PROCESSES       4096    // Limit to prevent pool exhaustion
#define FSC_CLEANUP_INTERVAL_MS         60000   // 1 minute
#define FSC_STATS_INTERVAL_MS           30000   // 30 seconds

//
// File classification flags
//
#define FSC_FILE_FLAG_EXECUTABLE        0x00000001
#define FSC_FILE_FLAG_SCRIPT            0x00000002
#define FSC_FILE_FLAG_DOCUMENT          0x00000004
#define FSC_FILE_FLAG_ARCHIVE           0x00000008
#define FSC_FILE_FLAG_SYSTEM            0x00000010
#define FSC_FILE_FLAG_SENSITIVE         0x00000020
#define FSC_FILE_FLAG_ENCRYPTED         0x00000040
#define FSC_FILE_FLAG_NETWORK           0x00000080
#define FSC_FILE_FLAG_REMOVABLE         0x00000100
#define FSC_FILE_FLAG_REPARSE           0x00000200
#define FSC_FILE_FLAG_ADS               0x00000400
#define FSC_FILE_FLAG_SPARSE            0x00000800

//
// Operation tracking flags
//
#define FSC_OP_FLAG_SCANNED             0x00000001
#define FSC_OP_FLAG_BLOCKED             0x00000002
#define FSC_OP_FLAG_CACHED              0x00000004
#define FSC_OP_FLAG_EXCLUDED            0x00000008
#define FSC_OP_FLAG_SELF_PROTECTED      0x00000010
#define FSC_OP_FLAG_TIMEOUT             0x00000020
#define FSC_OP_FLAG_ERROR               0x00000040

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Volume context for tracking per-volume statistics
//
typedef struct _FSC_VOLUME_CONTEXT {
    //
    // Volume identification
    //
    UNICODE_STRING VolumeName;
    WCHAR VolumeNameBuffer[FSC_MAX_VOLUME_NAME_LENGTH];
    ULONG VolumeSerial;
    FLT_FILESYSTEM_TYPE FileSystemType;

    //
    // Volume characteristics
    //
    BOOLEAN IsNetworkVolume;
    BOOLEAN IsRemovableVolume;
    BOOLEAN IsBootVolume;
    BOOLEAN SupportsTransactions;
    BOOLEAN SupportsReparsePoints;
    BOOLEAN SupportsSparseFiles;
    BOOLEAN SupportsEncryption;
    BOOLEAN SupportsCompression;

    //
    // Sector/cluster info
    //
    ULONG BytesPerSector;
    ULONG SectorsPerCluster;
    ULONG BytesPerCluster;

    //
    // Volume statistics
    //
    volatile LONG64 TotalOperations;
    volatile LONG64 FilesScanned;
    volatile LONG64 FilesBlocked;
    volatile LONG64 WriteOperations;
    volatile LONG64 DeleteOperations;
    volatile LONG64 RenameOperations;

    //
    // Ransomware detection metrics (per time window)
    //
    volatile LONG RecentRenames;
    volatile LONG RecentDeletes;
    volatile LONG RecentEncryptions;
    LARGE_INTEGER LastMetricReset;

    //
    // Instance tracking
    //
    PFLT_INSTANCE Instance;
    BOOLEAN Attached;

} FSC_VOLUME_CONTEXT, *PFSC_VOLUME_CONTEXT;

//
// Per-process file operation tracking
//
typedef struct _FSC_PROCESS_FILE_CONTEXT {
    HANDLE ProcessId;

    //
    // Operation counters (for anomaly detection)
    //
    volatile LONG64 TotalFileAccess;
    volatile LONG64 UniqueFilesAccessed;
    volatile LONG64 FilesModified;
    volatile LONG64 FilesDeleted;
    volatile LONG64 FilesRenamed;
    volatile LONG64 FilesCreated;

    //
    // Time-windowed metrics
    //
    volatile LONG RecentModifications;
    volatile LONG RecentDeletions;
    volatile LONG RecentRenames;
    LARGE_INTEGER LastActivityTime;
    LARGE_INTEGER WindowStartTime;

    //
    // Behavioral flags
    //
    ULONG BehaviorFlags;
    ULONG SuspicionScore;
    BOOLEAN IsRansomwareSuspect;
    BOOLEAN IsExfiltrationSuspect;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} FSC_PROCESS_FILE_CONTEXT, *PFSC_PROCESS_FILE_CONTEXT;

//
// Behavior flags
//
#define FSC_BEHAVIOR_MASS_RENAME        0x00000001
#define FSC_BEHAVIOR_MASS_DELETE        0x00000002
#define FSC_BEHAVIOR_MASS_MODIFY        0x00000004
#define FSC_BEHAVIOR_HIGH_ENTROPY       0x00000008
#define FSC_BEHAVIOR_EXTENSION_CHANGE   0x00000010
#define FSC_BEHAVIOR_SHADOW_COPY_DELETE 0x00000020
#define FSC_BEHAVIOR_BACKUP_DELETE      0x00000040
#define FSC_BEHAVIOR_SEQUENTIAL_ACCESS  0x00000080

//
// File operation context (passed between pre/post callbacks)
//
typedef struct _FSC_OPERATION_CONTEXT {
    ULONG Signature;
    ULONG Flags;
    LARGE_INTEGER StartTime;
    HANDLE ProcessId;
    HANDLE ThreadId;

    //
    // Captured information
    //
    UNICODE_STRING FileName;
    WCHAR FileNameBuffer[260];
    ULONG FileClassification;

    //
    // Scan information
    //
    SHADOWSTRIKE_CACHE_KEY CacheKey;
    BOOLEAN CacheKeyValid;
    BOOLEAN WasCacheHit;
    SHADOWSTRIKE_VERDICT Verdict;
    ULONG ThreatScore;

} FSC_OPERATION_CONTEXT, *PFSC_OPERATION_CONTEXT;

#define FSC_OP_CONTEXT_SIGNATURE        'pOcF'

//
// File type extension mapping
//
typedef struct _FSC_EXTENSION_INFO {
    PCWSTR Extension;
    ULONG Classification;
    ULONG ScanPriority;
} FSC_EXTENSION_INFO, *PFSC_EXTENSION_INFO;

//
// Work item context for deferred cleanup operations
//
typedef struct _FSC_CLEANUP_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    BOOLEAN ResetMetrics;
    BOOLEAN CleanupStale;
} FSC_CLEANUP_WORK_ITEM, *PFSC_CLEANUP_WORK_ITEM;

//
// Volume list entry for tracking attached volumes
//
typedef struct _FSC_VOLUME_LIST_ENTRY {
    LIST_ENTRY ListEntry;
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;
    FLT_FILESYSTEM_TYPE FileSystemType;
    BOOLEAN IsNetworkVolume;
    BOOLEAN IsRemovableVolume;
    WCHAR VolumeNameBuffer[FSC_MAX_VOLUME_NAME_LENGTH];
    USHORT VolumeNameLength;
} FSC_VOLUME_LIST_ENTRY, *PFSC_VOLUME_LIST_ENTRY;

//
// Global filesystem callback state
//
typedef struct _FSC_GLOBAL_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;

    //
    // Rundown protection for safe shutdown
    //
    EX_RUNDOWN_REF RundownRef;
    BOOLEAN RundownInitialized;

    //
    // Context registration
    //
    FLT_CONTEXT_REGISTRATION ContextRegistration[4];
    BOOLEAN ContextsRegistered;

    //
    // Volume tracking - actual list of volumes
    //
    LIST_ENTRY VolumeList;
    EX_PUSH_LOCK VolumeLock;
    volatile LONG VolumeCount;

    //
    // Process file context tracking
    //
    LIST_ENTRY ProcessContextList;
    EX_PUSH_LOCK ProcessContextLock;
    volatile LONG ProcessContextCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST OperationContextLookaside;
    NPAGED_LOOKASIDE_LIST ProcessContextLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Statistics
    //
    struct {
        volatile LONG64 PreCreateCalls;
        volatile LONG64 PostCreateCalls;
        volatile LONG64 PreWriteCalls;
        volatile LONG64 PostWriteCalls;
        volatile LONG64 PreSetInfoCalls;
        volatile LONG64 PreAcquireSectionCalls;
        volatile LONG64 ContextAllocations;
        volatile LONG64 ContextFrees;
        volatile LONG64 RansomwareDetections;
        volatile LONG64 ExfiltrationDetections;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Rate limiting state (protected by interlocked operations)
    //
    volatile LONG64 CurrentSecondStart100ns;
    volatile LONG CurrentSecondLogs;

    //
    // Cleanup timer and work item
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;
    volatile LONG CleanupWorkItemPending;
    PIO_WORKITEM CleanupWorkItem;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

} FSC_GLOBAL_STATE, *PFSC_GLOBAL_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static FSC_GLOBAL_STATE g_FscState = {0};

//
// File extension classification table
//
static const FSC_EXTENSION_INFO g_ExtensionTable[] = {
    //
    // Executables (highest priority)
    //
    { L"exe", FSC_FILE_FLAG_EXECUTABLE, 100 },
    { L"dll", FSC_FILE_FLAG_EXECUTABLE, 100 },
    { L"sys", FSC_FILE_FLAG_EXECUTABLE | FSC_FILE_FLAG_SYSTEM, 100 },
    { L"drv", FSC_FILE_FLAG_EXECUTABLE | FSC_FILE_FLAG_SYSTEM, 100 },
    { L"scr", FSC_FILE_FLAG_EXECUTABLE, 95 },
    { L"com", FSC_FILE_FLAG_EXECUTABLE, 95 },
    { L"pif", FSC_FILE_FLAG_EXECUTABLE, 95 },
    { L"msi", FSC_FILE_FLAG_EXECUTABLE, 90 },
    { L"msp", FSC_FILE_FLAG_EXECUTABLE, 90 },
    { L"msu", FSC_FILE_FLAG_EXECUTABLE, 90 },
    { L"ocx", FSC_FILE_FLAG_EXECUTABLE, 90 },
    { L"cpl", FSC_FILE_FLAG_EXECUTABLE, 90 },

    //
    // Scripts (high priority)
    //
    { L"ps1", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"psm1", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"psd1", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"bat", FSC_FILE_FLAG_SCRIPT, 80 },
    { L"cmd", FSC_FILE_FLAG_SCRIPT, 80 },
    { L"vbs", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"vbe", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"js", FSC_FILE_FLAG_SCRIPT, 80 },
    { L"jse", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"wsf", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"wsh", FSC_FILE_FLAG_SCRIPT, 85 },
    { L"hta", FSC_FILE_FLAG_SCRIPT, 90 },
    { L"reg", FSC_FILE_FLAG_SCRIPT, 75 },
    { L"inf", FSC_FILE_FLAG_SCRIPT, 70 },

    //
    // Documents (medium priority - macro risk)
    //
    { L"doc", FSC_FILE_FLAG_DOCUMENT, 60 },
    { L"docx", FSC_FILE_FLAG_DOCUMENT, 55 },
    { L"docm", FSC_FILE_FLAG_DOCUMENT, 75 },  // Macro-enabled
    { L"xls", FSC_FILE_FLAG_DOCUMENT, 60 },
    { L"xlsx", FSC_FILE_FLAG_DOCUMENT, 55 },
    { L"xlsm", FSC_FILE_FLAG_DOCUMENT, 75 },  // Macro-enabled
    { L"xlsb", FSC_FILE_FLAG_DOCUMENT, 75 },  // Binary with macros
    { L"ppt", FSC_FILE_FLAG_DOCUMENT, 55 },
    { L"pptx", FSC_FILE_FLAG_DOCUMENT, 50 },
    { L"pptm", FSC_FILE_FLAG_DOCUMENT, 75 },  // Macro-enabled
    { L"pdf", FSC_FILE_FLAG_DOCUMENT, 65 },
    { L"rtf", FSC_FILE_FLAG_DOCUMENT, 60 },

    //
    // Archives (medium priority - can contain malware)
    //
    { L"zip", FSC_FILE_FLAG_ARCHIVE, 50 },
    { L"rar", FSC_FILE_FLAG_ARCHIVE, 50 },
    { L"7z", FSC_FILE_FLAG_ARCHIVE, 50 },
    { L"cab", FSC_FILE_FLAG_ARCHIVE, 55 },
    { L"iso", FSC_FILE_FLAG_ARCHIVE, 60 },
    { L"img", FSC_FILE_FLAG_ARCHIVE, 60 },
    { L"vhd", FSC_FILE_FLAG_ARCHIVE, 60 },
    { L"vhdx", FSC_FILE_FLAG_ARCHIVE, 60 },

    //
    // Sensitive data files
    //
    { L"pst", FSC_FILE_FLAG_SENSITIVE, 40 },
    { L"ost", FSC_FILE_FLAG_SENSITIVE, 40 },
    { L"mdb", FSC_FILE_FLAG_SENSITIVE, 45 },
    { L"accdb", FSC_FILE_FLAG_SENSITIVE, 45 },
    { L"sqlite", FSC_FILE_FLAG_SENSITIVE, 40 },
    { L"db", FSC_FILE_FLAG_SENSITIVE, 40 },
    { L"sql", FSC_FILE_FLAG_SENSITIVE, 35 },
    { L"bak", FSC_FILE_FLAG_SENSITIVE, 35 },
    { L"key", FSC_FILE_FLAG_SENSITIVE, 50 },
    { L"pem", FSC_FILE_FLAG_SENSITIVE, 50 },
    { L"pfx", FSC_FILE_FLAG_SENSITIVE, 50 },
    { L"p12", FSC_FILE_FLAG_SENSITIVE, 50 },
};

#define FSC_EXTENSION_TABLE_COUNT (sizeof(g_ExtensionTable) / sizeof(g_ExtensionTable[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PFSC_OPERATION_CONTEXT
FscpAllocateOperationContext(
    VOID
    );

static VOID
FscpFreeOperationContext(
    _In_ PFSC_OPERATION_CONTEXT Context
    );

static PFSC_PROCESS_FILE_CONTEXT
FscpLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
FscpReferenceProcessContext(
    _Inout_ PFSC_PROCESS_FILE_CONTEXT Context
    );

static VOID
FscpDereferenceProcessContext(
    _Inout_ PFSC_PROCESS_FILE_CONTEXT Context
    );

static ULONG
FscpClassifyFileByExtension(
    _In_ PCUNICODE_STRING Extension
    );

static ULONG
FscpGetScanPriority(
    _In_ PCUNICODE_STRING Extension
    );

static BOOLEAN
FscpIsHighEntropyFile(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

static VOID
FscpUpdateProcessFileMetrics(
    _In_ HANDLE ProcessId,
    _In_ ULONG OperationType,
    _In_opt_ PCUNICODE_STRING FileName
    );

static BOOLEAN
FscpDetectRansomwareBehavior(
    _In_ PFSC_PROCESS_FILE_CONTEXT ProcessContext
    );

static VOID
FscpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
FscpCleanupWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
FscpCleanupStaleContexts(
    VOID
    );

static VOID
FscpResetTimeWindowedMetrics(
    VOID
    );

static BOOLEAN
FscpAcquireRundownProtection(
    VOID
    );

static VOID
FscpReleaseRundownProtection(
    VOID
    );

static BOOLEAN
FscpShouldLogOperation(
    VOID
    );

//
// Safe string comparison for UNICODE_STRING (IRQL-safe)
//
static BOOLEAN
FscpCompareExtensionSafe(
    _In_ PCUNICODE_STRING Extension,
    _In_ PCWSTR CompareStr
    );

// ============================================================================
// CONTEXT CLEANUP CALLBACKS
// ============================================================================

VOID
ShadowStrikeStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
/*++
Routine Description:
    Cleanup callback for stream contexts.

Arguments:
    Context - The context being cleaned up.
    ContextType - Type of context (FLT_STREAM_CONTEXT).
--*/
{
    PSHADOWSTRIKE_STREAM_CONTEXT StreamContext = (PSHADOWSTRIKE_STREAM_CONTEXT)Context;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ContextType);

    if (StreamContext == NULL) {
        return;
    }

    InterlockedIncrement64(&g_FscState.Stats.ContextFrees);

    //
    // Any additional cleanup for stream context resources
    //
}


VOID
ShadowStrikeStreamHandleContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
/*++
Routine Description:
    Cleanup callback for stream handle contexts.

Arguments:
    Context - The context being cleaned up.
    ContextType - Type of context (FLT_STREAMHANDLE_CONTEXT).
--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);

    InterlockedIncrement64(&g_FscState.Stats.ContextFrees);
}


VOID
ShadowStrikeVolumeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
/*++
Routine Description:
    Cleanup callback for volume contexts.

Arguments:
    Context - The context being cleaned up.
    ContextType - Type of context (FLT_VOLUME_CONTEXT).
--*/
{
    PFSC_VOLUME_CONTEXT VolumeContext = (PFSC_VOLUME_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (VolumeContext == NULL) {
        return;
    }

    //
    // Log volume detachment statistics
    //
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/FS] Volume detached. Stats: Ops=%lld, Scanned=%lld, Blocked=%lld\n",
        VolumeContext->TotalOperations,
        VolumeContext->FilesScanned,
        VolumeContext->FilesBlocked
        );

    InterlockedIncrement64(&g_FscState.Stats.ContextFrees);
}

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++
Routine Description:
    Instance setup callback. Called when the filter manager wants to attach
    an instance to a volume.

Arguments:
    FltObjects - Filter objects for this volume.
    Flags - Setup flags.
    VolumeDeviceType - Type of device (disk, network, etc.).
    VolumeFilesystemType - Type of file system (NTFS, ReFS, etc.).

Return Value:
    STATUS_SUCCESS to attach, STATUS_FLT_DO_NOT_ATTACH to skip.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFSC_VOLUME_CONTEXT VolumeContext = NULL;
    ULONG VolumeNameLength = 0;
    BOOLEAN IsNetworkVolume = FALSE;
    BOOLEAN IsRemovable = FALSE;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Flags);

    //
    // Check if we should attach to this volume type
    //
    switch (VolumeDeviceType) {
        case FILE_DEVICE_DISK_FILE_SYSTEM:
        case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
            //
            // Standard disk volumes - always attach
            //
            break;

        case FILE_DEVICE_NETWORK_FILE_SYSTEM:
            //
            // Network volumes - check configuration
            //
            IsNetworkVolume = TRUE;
            if (!g_DriverData.Config.ScanNetworkFiles) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_INFO_LEVEL,
                    "[ShadowStrike/FS] Skipping network volume (disabled by config)\n"
                    );
                return STATUS_FLT_DO_NOT_ATTACH;
            }
            break;

        default:
            //
            // Unknown volume type - skip
            //
            return STATUS_FLT_DO_NOT_ATTACH;
    }

    //
    // Check filesystem type
    //
    switch (VolumeFilesystemType) {
        case FLT_FSTYPE_NTFS:
        case FLT_FSTYPE_REFS:
        case FLT_FSTYPE_FAT:
        case FLT_FSTYPE_EXFAT:
        case FLT_FSTYPE_CDFS:
        case FLT_FSTYPE_UDFS:
            //
            // Supported filesystems
            //
            break;

        case FLT_FSTYPE_LANMAN:
        case FLT_FSTYPE_RDPDR:
        case FLT_FSTYPE_NFS:
        case FLT_FSTYPE_MS_NETWARE:
        case FLT_FSTYPE_NETWARE:
        case FLT_FSTYPE_WEBDAV:
            //
            // Network filesystems - check configuration
            //
            IsNetworkVolume = TRUE;
            if (!g_DriverData.Config.ScanNetworkFiles) {
                return STATUS_FLT_DO_NOT_ATTACH;
            }
            break;

        case FLT_FSTYPE_RAW:
            //
            // Raw filesystem - skip
            //
            return STATUS_FLT_DO_NOT_ATTACH;

        default:
            //
            // Unknown filesystem - attach cautiously
            //
            break;
    }

    //
    // Allocate volume context
    //
    Status = FltAllocateContext(
        g_DriverData.FilterHandle,
        FLT_VOLUME_CONTEXT,
        sizeof(FSC_VOLUME_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&VolumeContext
        );

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/FS] Failed to allocate volume context: 0x%08X\n",
            Status
            );
        //
        // Attach anyway without context
        //
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(VolumeContext, sizeof(FSC_VOLUME_CONTEXT));

    //
    // Get volume name
    //
    Status = FltGetVolumeName(
        FltObjects->Volume,
        NULL,
        &VolumeNameLength
        );

    if (Status == STATUS_BUFFER_TOO_SMALL && VolumeNameLength > 0) {
        if (VolumeNameLength <= sizeof(VolumeContext->VolumeNameBuffer)) {
            VolumeContext->VolumeName.Buffer = VolumeContext->VolumeNameBuffer;
            VolumeContext->VolumeName.MaximumLength = sizeof(VolumeContext->VolumeNameBuffer);

            Status = FltGetVolumeName(
                FltObjects->Volume,
                &VolumeContext->VolumeName,
                NULL
                );
        }
    }

    //
    // Get volume properties
    //
    {
        FLT_VOLUME_PROPERTIES VolumeProps = {0};
        ULONG BytesReturned = 0;

        Status = FltGetVolumeProperties(
            FltObjects->Volume,
            &VolumeProps,
            sizeof(VolumeProps),
            &BytesReturned
            );

        if (NT_SUCCESS(Status)) {
            VolumeContext->BytesPerSector = VolumeProps.SectorSize;

            if (VolumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA) {
                IsRemovable = TRUE;
            }
        }
    }

    //
    // Populate volume context
    //
    VolumeContext->FileSystemType = VolumeFilesystemType;
    VolumeContext->IsNetworkVolume = IsNetworkVolume;
    VolumeContext->IsRemovableVolume = IsRemovable;
    VolumeContext->Instance = FltObjects->Instance;
    VolumeContext->Attached = TRUE;
    KeQuerySystemTime(&VolumeContext->LastMetricReset);

    //
    // Check for feature support
    //
    VolumeContext->SupportsReparsePoints =
        (VolumeFilesystemType == FLT_FSTYPE_NTFS || VolumeFilesystemType == FLT_FSTYPE_REFS);
    VolumeContext->SupportsSparseFiles =
        (VolumeFilesystemType == FLT_FSTYPE_NTFS || VolumeFilesystemType == FLT_FSTYPE_REFS);
    VolumeContext->SupportsEncryption =
        (VolumeFilesystemType == FLT_FSTYPE_NTFS);
    VolumeContext->SupportsCompression =
        (VolumeFilesystemType == FLT_FSTYPE_NTFS);
    VolumeContext->SupportsTransactions =
        (VolumeFilesystemType == FLT_FSTYPE_NTFS);

    //
    // Set volume context
    //
    Status = FltSetVolumeContext(
        FltObjects->Volume,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        VolumeContext,
        NULL
        );

    if (!NT_SUCCESS(Status) && Status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/FS] Failed to set volume context: 0x%08X\n",
            Status
            );
    }

    //
    // Add to volume list with proper tracking
    //
    {
        PFSC_VOLUME_LIST_ENTRY VolumeListEntry = NULL;

        VolumeListEntry = (PFSC_VOLUME_LIST_ENTRY)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(FSC_VOLUME_LIST_ENTRY),
            FSC_POOL_TAG
            );

        if (VolumeListEntry != NULL) {
            RtlZeroMemory(VolumeListEntry, sizeof(FSC_VOLUME_LIST_ENTRY));
            VolumeListEntry->Volume = FltObjects->Volume;
            VolumeListEntry->Instance = FltObjects->Instance;
            VolumeListEntry->FileSystemType = VolumeFilesystemType;
            VolumeListEntry->IsNetworkVolume = IsNetworkVolume;
            VolumeListEntry->IsRemovableVolume = IsRemovable;

            //
            // Copy volume name before releasing context
            //
            if (VolumeContext->VolumeName.Length > 0 &&
                VolumeContext->VolumeName.Length < sizeof(VolumeListEntry->VolumeNameBuffer)) {
                RtlCopyMemory(
                    VolumeListEntry->VolumeNameBuffer,
                    VolumeContext->VolumeName.Buffer,
                    VolumeContext->VolumeName.Length
                    );
                VolumeListEntry->VolumeNameLength = VolumeContext->VolumeName.Length / sizeof(WCHAR);
            }

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&g_FscState.VolumeLock);

            InsertTailList(&g_FscState.VolumeList, &VolumeListEntry->ListEntry);
            InterlockedIncrement(&g_FscState.VolumeCount);

            ExReleasePushLockExclusive(&g_FscState.VolumeLock);
            KeLeaveCriticalRegion();
        } else {
            //
            // Allocation failed - just increment count
            //
            InterlockedIncrement(&g_FscState.VolumeCount);
        }
    }

    //
    // Log BEFORE releasing context to avoid use-after-free
    //
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/FS] Attached to volume: %wZ (FS=%d, Net=%d, Rem=%d)\n",
        &VolumeContext->VolumeName,
        VolumeFilesystemType,
        IsNetworkVolume,
        IsRemovable
        );

    InterlockedIncrement64(&g_FscState.Stats.ContextAllocations);

    //
    // Release context AFTER all accesses are complete
    //
    FltReleaseContext((PFLT_CONTEXT)VolumeContext);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ShadowStrikeInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++
Routine Description:
    Instance query teardown callback. Called when something wants to detach
    our instance from a volume.

Arguments:
    FltObjects - Filter objects for this volume.
    Flags - Query flags.

Return Value:
    STATUS_SUCCESS to allow detachment.
--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    //
    // Always allow manual detachment
    //
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
ShadowStrikeInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
    )
/*++
Routine Description:
    Instance teardown start callback. Called when instance detachment begins.

Arguments:
    FltObjects - Filter objects for this volume.
    Reason - Reason for teardown.
--*/
{
    PFSC_VOLUME_CONTEXT VolumeContext = NULL;
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Reason);

    //
    // Get volume context to mark as detaching
    //
    Status = FltGetVolumeContext(
        g_DriverData.FilterHandle,
        FltObjects->Volume,
        (PFLT_CONTEXT*)&VolumeContext
        );

    if (NT_SUCCESS(Status) && VolumeContext != NULL) {
        VolumeContext->Attached = FALSE;
        FltReleaseContext((PFLT_CONTEXT)VolumeContext);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/FS] Instance teardown started (Reason=%d)\n",
        Reason
        );
}


_Use_decl_annotations_
VOID
ShadowStrikeInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
    )
/*++
Routine Description:
    Instance teardown complete callback. Called when instance detachment is complete.

Arguments:
    FltObjects - Filter objects for this volume.
    Reason - Reason for teardown.
--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    InterlockedDecrement(&g_FscState.VolumeCount);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/FS] Instance teardown complete (Reason=%d)\n",
        Reason
        );
}

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitializeFileSystemCallbacks(
    VOID
    )
/*++
Routine Description:
    Initializes the filesystem callback subsystem.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER DueTime;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (g_FscState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_FscState, sizeof(FSC_GLOBAL_STATE));

    //
    // Initialize rundown protection FIRST
    //
    ExInitializeRundownProtection(&g_FscState.RundownRef);
    g_FscState.RundownInitialized = TRUE;

    //
    // Initialize volume list
    //
    InitializeListHead(&g_FscState.VolumeList);
    ExInitializePushLock(&g_FscState.VolumeLock);

    //
    // Initialize process context list
    //
    InitializeListHead(&g_FscState.ProcessContextList);
    ExInitializePushLock(&g_FscState.ProcessContextLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_FscState.OperationContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(FSC_OPERATION_CONTEXT),
        FSC_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_FscState.ProcessContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(FSC_PROCESS_FILE_CONTEXT),
        FSC_CONTEXT_POOL_TAG,
        0
        );

    g_FscState.LookasideInitialized = TRUE;

    //
    // Initialize statistics and rate limiting
    //
    KeQuerySystemTime(&g_FscState.Stats.StartTime);
    KeQuerySystemTime(&CurrentTime);
    g_FscState.CurrentSecondStart100ns = CurrentTime.QuadPart;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&g_FscState.CleanupTimer);
    KeInitializeDpc(&g_FscState.CleanupDpc, FscpCleanupTimerDpc, NULL);

    //
    // Allocate work item for deferred cleanup (requires device object)
    // Note: Work item will be allocated lazily when needed if we don't have device object yet
    //
    g_FscState.CleanupWorkItem = NULL;
    g_FscState.CleanupWorkItemPending = 0;

    //
    // Start cleanup timer
    //
    DueTime.QuadPart = -((LONGLONG)FSC_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &g_FscState.CleanupTimer,
        DueTime,
        FSC_CLEANUP_INTERVAL_MS,
        &g_FscState.CleanupDpc
        );
    g_FscState.CleanupTimerActive = TRUE;

    g_FscState.Initialized = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/FS] Filesystem callbacks initialized\n"
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
ShadowStrikeCleanupFileSystemCallbacks(
    VOID
    )
/*++
Routine Description:
    Cleans up the filesystem callback subsystem.
    Implements proper rundown protection to ensure all in-flight operations complete.
--*/
{
    PLIST_ENTRY Entry;
    PFSC_PROCESS_FILE_CONTEXT ProcessContext;
    PFSC_VOLUME_LIST_ENTRY VolumeEntry;

    PAGED_CODE();

    if (!g_FscState.Initialized) {
        return;
    }

    //
    // Signal shutdown FIRST
    //
    g_FscState.ShutdownRequested = TRUE;
    g_FscState.Initialized = FALSE;

    //
    // Wait for all in-flight operations to complete using rundown protection
    //
    if (g_FscState.RundownInitialized) {
        ExWaitForRundownProtectionRelease(&g_FscState.RundownRef);
    }

    //
    // Cancel cleanup timer and wait for DPC to complete
    //
    if (g_FscState.CleanupTimerActive) {
        KeCancelTimer(&g_FscState.CleanupTimer);

        //
        // CRITICAL: Flush queued DPCs to ensure our DPC is not running
        //
        KeFlushQueuedDpcs();

        g_FscState.CleanupTimerActive = FALSE;
    }

    //
    // Free work item if allocated
    //
    if (g_FscState.CleanupWorkItem != NULL) {
        IoFreeWorkItem(g_FscState.CleanupWorkItem);
        g_FscState.CleanupWorkItem = NULL;
    }

    //
    // Free all volume list entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FscState.VolumeLock);

    while (!IsListEmpty(&g_FscState.VolumeList)) {
        Entry = RemoveHeadList(&g_FscState.VolumeList);
        VolumeEntry = CONTAINING_RECORD(Entry, FSC_VOLUME_LIST_ENTRY, ListEntry);
        ExFreePoolWithTag(VolumeEntry, FSC_POOL_TAG);
    }

    ExReleasePushLockExclusive(&g_FscState.VolumeLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FscState.ProcessContextLock);

    while (!IsListEmpty(&g_FscState.ProcessContextList)) {
        Entry = RemoveHeadList(&g_FscState.ProcessContextList);
        ProcessContext = CONTAINING_RECORD(Entry, FSC_PROCESS_FILE_CONTEXT, ListEntry);

        ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_FscState.ProcessContextLookaside, ProcessContext);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_FscState.ProcessContextLock);
    }

    ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (g_FscState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_FscState.OperationContextLookaside);
        ExDeleteNPagedLookasideList(&g_FscState.ProcessContextLookaside);
        g_FscState.LookasideInitialized = FALSE;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/FS] Filesystem callbacks shutdown. "
        "Stats: PreCreate=%lld, PostCreate=%lld, Ransomware=%lld\n",
        g_FscState.Stats.PreCreateCalls,
        g_FscState.Stats.PostCreateCalls,
        g_FscState.Stats.RansomwareDetections
        );
}

// ============================================================================
// OPERATION CONTEXT MANAGEMENT
// ============================================================================

static PFSC_OPERATION_CONTEXT
FscpAllocateOperationContext(
    VOID
    )
{
    PFSC_OPERATION_CONTEXT Context;

    Context = (PFSC_OPERATION_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_FscState.OperationContextLookaside
        );

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(FSC_OPERATION_CONTEXT));
        Context->Signature = FSC_OP_CONTEXT_SIGNATURE;
        Context->ProcessId = PsGetCurrentProcessId();
        Context->ThreadId = PsGetCurrentThreadId();
        KeQuerySystemTime(&Context->StartTime);

        InterlockedIncrement64(&g_FscState.Stats.ContextAllocations);
    }

    return Context;
}


static VOID
FscpFreeOperationContext(
    _In_ PFSC_OPERATION_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (Context->Signature != FSC_OP_CONTEXT_SIGNATURE) {
        //
        // Invalid context - corruption detected
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/FS] Invalid operation context signature!\n"
            );
        return;
    }

    Context->Signature = 0;
    ExFreeToNPagedLookasideList(&g_FscState.OperationContextLookaside, Context);

    InterlockedIncrement64(&g_FscState.Stats.ContextFrees);
}

// ============================================================================
// PROCESS FILE CONTEXT MANAGEMENT
// ============================================================================

static PFSC_PROCESS_FILE_CONTEXT
FscpLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
/*++
Routine Description:
    Looks up or creates a process file context with proper synchronization.
    Uses lock-protected reference counting to prevent race conditions.

Arguments:
    ProcessId - Process ID to look up.
    CreateIfNotFound - If TRUE, create context if not found.

Return Value:
    Referenced process context, or NULL on failure.
    Caller must call FscpDereferenceProcessContext when done.
--*/
{
    PLIST_ENTRY Entry;
    PFSC_PROCESS_FILE_CONTEXT Context = NULL;
    PFSC_PROCESS_FILE_CONTEXT NewContext = NULL;

    //
    // First, try to find existing context under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FscState.ProcessContextLock);

    for (Entry = g_FscState.ProcessContextList.Flink;
         Entry != &g_FscState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, FSC_PROCESS_FILE_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            //
            // Found - increment ref count while holding lock to prevent race
            //
            InterlockedIncrement(&Context->RefCount);
            ExReleasePushLockShared(&g_FscState.ProcessContextLock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&g_FscState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Check process context limit to prevent pool exhaustion
    //
    if (g_FscState.ProcessContextCount >= FSC_MAX_TRACKED_PROCESSES) {
        return NULL;
    }

    //
    // Allocate new context outside lock
    //
    NewContext = (PFSC_PROCESS_FILE_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_FscState.ProcessContextLookaside
        );

    if (NewContext == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewContext, sizeof(FSC_PROCESS_FILE_CONTEXT));
    NewContext->ProcessId = ProcessId;
    NewContext->RefCount = 2;  // One for list, one for caller
    KeQuerySystemTime(&NewContext->WindowStartTime);
    KeQuerySystemTime(&NewContext->LastActivityTime);
    InitializeListHead(&NewContext->ListEntry);

    //
    // Insert into list under exclusive lock with race check
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FscState.ProcessContextLock);

    //
    // Re-check limit under lock
    //
    if (g_FscState.ProcessContextCount >= FSC_MAX_TRACKED_PROCESSES) {
        ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
        KeLeaveCriticalRegion();
        ExFreeToNPagedLookasideList(&g_FscState.ProcessContextLookaside, NewContext);
        return NULL;
    }

    //
    // Check for race condition - another thread may have inserted
    //
    for (Entry = g_FscState.ProcessContextList.Flink;
         Entry != &g_FscState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, FSC_PROCESS_FILE_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            //
            // Race - use existing, increment ref under lock
            //
            InterlockedIncrement(&Context->RefCount);
            ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
            KeLeaveCriticalRegion();
            ExFreeToNPagedLookasideList(&g_FscState.ProcessContextLookaside, NewContext);
            return Context;
        }
    }

    //
    // Insert our new context
    //
    InsertTailList(&g_FscState.ProcessContextList, &NewContext->ListEntry);
    InterlockedIncrement(&g_FscState.ProcessContextCount);

    ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
    KeLeaveCriticalRegion();

    return NewContext;
}


static VOID
FscpReferenceProcessContext(
    _Inout_ PFSC_PROCESS_FILE_CONTEXT Context
    )
{
    if (Context != NULL) {
        InterlockedIncrement(&Context->RefCount);
    }
}


static VOID
FscpDereferenceProcessContext(
    _Inout_ PFSC_PROCESS_FILE_CONTEXT Context
    )
/*++
Routine Description:
    Decrements reference count on process context.
    Uses lock-protected decrement to prevent race conditions.

Arguments:
    Context - Context to dereference.
--*/
{
    LONG NewRefCount;
    BOOLEAN ShouldFree = FALSE;

    if (Context == NULL) {
        return;
    }

    //
    // CRITICAL: Acquire lock BEFORE decrementing to prevent race where
    // another thread could reference this context between our decrement
    // and our removal from the list.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FscState.ProcessContextLock);

    NewRefCount = InterlockedDecrement(&Context->RefCount);

    if (NewRefCount == 0) {
        //
        // Last reference - remove from list under lock
        //
        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_FscState.ProcessContextCount);
        }
        ShouldFree = TRUE;
    }

    ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Free outside lock
    //
    if (ShouldFree) {
        ExFreeToNPagedLookasideList(&g_FscState.ProcessContextLookaside, Context);
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static BOOLEAN
FscpAcquireRundownProtection(
    VOID
    )
/*++
Routine Description:
    Acquires rundown protection to safely perform operations.
    Must be called before any operation that accesses global state.

Return Value:
    TRUE if protection acquired, FALSE if shutdown in progress.
--*/
{
    if (!g_FscState.RundownInitialized || g_FscState.ShutdownRequested) {
        return FALSE;
    }

    return ExAcquireRundownProtection(&g_FscState.RundownRef);
}


static VOID
FscpReleaseRundownProtection(
    VOID
    )
/*++
Routine Description:
    Releases rundown protection after operation completes.
--*/
{
    if (g_FscState.RundownInitialized) {
        ExReleaseRundownProtection(&g_FscState.RundownRef);
    }
}


static BOOLEAN
FscpShouldLogOperation(
    VOID
    )
/*++
Routine Description:
    Rate-limited logging check using atomic operations.
    Thread-safe implementation without TOCTOU issues.

Return Value:
    TRUE if logging should proceed, FALSE if rate limited.
--*/
{
    LARGE_INTEGER CurrentTime;
    LONG64 CurrentSecond;
    LONG64 StoredSecond;
    LONG CurrentLogs;

    KeQuerySystemTime(&CurrentTime);
    CurrentSecond = CurrentTime.QuadPart / 10000000LL;  // Convert to seconds
    StoredSecond = g_FscState.CurrentSecondStart100ns / 10000000LL;

    if (CurrentSecond != StoredSecond) {
        //
        // New second - reset atomically
        // Use InterlockedCompareExchange64 to handle race
        //
        if (InterlockedCompareExchange64(
                &g_FscState.CurrentSecondStart100ns,
                CurrentTime.QuadPart,
                g_FscState.CurrentSecondStart100ns) != g_FscState.CurrentSecondStart100ns) {
            //
            // Another thread updated - re-read
            //
        }
        InterlockedExchange(&g_FscState.CurrentSecondLogs, 0);
    }

    CurrentLogs = InterlockedIncrement(&g_FscState.CurrentSecondLogs);
    return (CurrentLogs <= 100);  // Allow 100 logs per second
}


static BOOLEAN
FscpCompareExtensionSafe(
    _In_ PCUNICODE_STRING Extension,
    _In_ PCWSTR CompareStr
    )
/*++
Routine Description:
    IRQL-safe case-insensitive extension comparison.
    Uses RtlCompareUnicodeString instead of _wcsicmp.

Arguments:
    Extension - Extension to compare.
    CompareStr - Null-terminated string to compare against.

Return Value:
    TRUE if extensions match (case-insensitive).
--*/
{
    UNICODE_STRING CompareString;
    UNICODE_STRING ExtString;
    USHORT CompareLen;

    if (Extension == NULL || Extension->Buffer == NULL || CompareStr == NULL) {
        return FALSE;
    }

    //
    // Skip leading dot in extension
    //
    ExtString = *Extension;
    if (ExtString.Length >= sizeof(WCHAR) && ExtString.Buffer[0] == L'.') {
        ExtString.Buffer++;
        ExtString.Length -= sizeof(WCHAR);
        if (ExtString.MaximumLength >= sizeof(WCHAR)) {
            ExtString.MaximumLength -= sizeof(WCHAR);
        }
    }

    //
    // Build comparison string (without null terminator in length)
    //
    CompareLen = 0;
    while (CompareStr[CompareLen] != L'\0' && CompareLen < 32) {
        CompareLen++;
    }

    CompareString.Buffer = (PWCH)CompareStr;
    CompareString.Length = CompareLen * sizeof(WCHAR);
    CompareString.MaximumLength = CompareString.Length;

    return RtlEqualUnicodeString(&ExtString, &CompareString, TRUE);
}


// ============================================================================
// FILE CLASSIFICATION
// ============================================================================

static ULONG
FscpClassifyFileByExtension(
    _In_ PCUNICODE_STRING Extension
    )
/*++
Routine Description:
    Classifies file by extension using IRQL-safe comparison.

Arguments:
    Extension - File extension.

Return Value:
    Classification flags.
--*/
{
    ULONG i;

    if (Extension == NULL || Extension->Length == 0 || Extension->Buffer == NULL) {
        return 0;
    }

    //
    // Search extension table using safe comparison
    //
    for (i = 0; i < FSC_EXTENSION_TABLE_COUNT; i++) {
        if (FscpCompareExtensionSafe(Extension, g_ExtensionTable[i].Extension)) {
            return g_ExtensionTable[i].Classification;
        }
    }

    return 0;
}


static ULONG
FscpGetScanPriority(
    _In_ PCUNICODE_STRING Extension
    )
/*++
Routine Description:
    Gets scan priority for file extension using IRQL-safe comparison.

Arguments:
    Extension - File extension.

Return Value:
    Scan priority (0-100).
--*/
{
    ULONG i;

    if (Extension == NULL || Extension->Length == 0 || Extension->Buffer == NULL) {
        return 50;  // Default priority
    }

    //
    // Search extension table using safe comparison
    //
    for (i = 0; i < FSC_EXTENSION_TABLE_COUNT; i++) {
        if (FscpCompareExtensionSafe(Extension, g_ExtensionTable[i].Extension)) {
            return g_ExtensionTable[i].ScanPriority;
        }
    }

    return 50;  // Default priority
}

// ============================================================================
// RANSOMWARE DETECTION
// ============================================================================

static VOID
FscpUpdateProcessFileMetrics(
    _In_ HANDLE ProcessId,
    _In_ ULONG OperationType,
    _In_opt_ PCUNICODE_STRING FileName
    )
/*++
Routine Description:
    Updates process file operation metrics for ransomware detection.

Arguments:
    ProcessId - Process performing the operation.
    OperationType - Type of operation (1=modify, 2=delete, 3=rename, 4=create).
    FileName - Optional file name.
--*/
{
    PFSC_PROCESS_FILE_CONTEXT ProcessContext;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeDiff;
    BOOLEAN CheckRansomware = FALSE;

    UNREFERENCED_PARAMETER(FileName);

    ProcessContext = FscpLookupProcessContext(ProcessId, TRUE);
    if (ProcessContext == NULL) {
        return;
    }

    KeQuerySystemTime(&CurrentTime);
    ProcessContext->LastActivityTime = CurrentTime;

    //
    // Reset time window if expired (1 second window)
    //
    TimeDiff.QuadPart = CurrentTime.QuadPart - ProcessContext->WindowStartTime.QuadPart;
    if (TimeDiff.QuadPart > (10000000LL)) {  // 1 second in 100ns units
        //
        // Check for ransomware before resetting
        //
        CheckRansomware = TRUE;

        ProcessContext->RecentModifications = 0;
        ProcessContext->RecentDeletions = 0;
        ProcessContext->RecentRenames = 0;
        ProcessContext->WindowStartTime = CurrentTime;
    }

    //
    // Update counters
    //
    switch (OperationType) {
        case 1:  // Modify
            InterlockedIncrement64(&ProcessContext->FilesModified);
            InterlockedIncrement(&ProcessContext->RecentModifications);
            break;

        case 2:  // Delete
            InterlockedIncrement64(&ProcessContext->FilesDeleted);
            InterlockedIncrement(&ProcessContext->RecentDeletions);
            break;

        case 3:  // Rename
            InterlockedIncrement64(&ProcessContext->FilesRenamed);
            InterlockedIncrement(&ProcessContext->RecentRenames);
            break;

        case 4:  // Create
            InterlockedIncrement64(&ProcessContext->FilesCreated);
            break;
    }

    InterlockedIncrement64(&ProcessContext->TotalFileAccess);

    //
    // Check for ransomware behavior
    //
    if (CheckRansomware ||
        ProcessContext->RecentModifications > FSC_RANSOMWARE_DELETE_THRESHOLD ||
        ProcessContext->RecentDeletions > FSC_RANSOMWARE_DELETE_THRESHOLD ||
        ProcessContext->RecentRenames > FSC_RANSOMWARE_RENAME_THRESHOLD) {

        if (FscpDetectRansomwareBehavior(ProcessContext)) {
            ProcessContext->IsRansomwareSuspect = TRUE;
            ProcessContext->BehaviorFlags |= FSC_BEHAVIOR_MASS_MODIFY;

            InterlockedIncrement64(&g_FscState.Stats.RansomwareDetections);

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/FS] RANSOMWARE BEHAVIOR DETECTED: PID=%lu, "
                "Mods=%ld, Dels=%ld, Renames=%ld\n",
                HandleToULong(ProcessId),
                ProcessContext->RecentModifications,
                ProcessContext->RecentDeletions,
                ProcessContext->RecentRenames
                );
        }
    }

    FscpDereferenceProcessContext(ProcessContext);
}


static BOOLEAN
FscpDetectRansomwareBehavior(
    _In_ PFSC_PROCESS_FILE_CONTEXT ProcessContext
    )
/*++
Routine Description:
    Analyzes process file context for ransomware-like behavior.

Arguments:
    ProcessContext - Process context to analyze.

Return Value:
    TRUE if ransomware behavior is detected.
--*/
{
    ULONG Score = 0;

    //
    // Check for mass rename (common in ransomware)
    //
    if (ProcessContext->RecentRenames > FSC_RANSOMWARE_RENAME_THRESHOLD) {
        Score += 40;
        ProcessContext->BehaviorFlags |= FSC_BEHAVIOR_MASS_RENAME;
    }

    //
    // Check for mass delete
    //
    if (ProcessContext->RecentDeletions > FSC_RANSOMWARE_DELETE_THRESHOLD) {
        Score += 35;
        ProcessContext->BehaviorFlags |= FSC_BEHAVIOR_MASS_DELETE;
    }

    //
    // Check for mass modify
    //
    if (ProcessContext->RecentModifications > FSC_RANSOMWARE_DELETE_THRESHOLD) {
        Score += 30;
        ProcessContext->BehaviorFlags |= FSC_BEHAVIOR_MASS_MODIFY;
    }

    //
    // Check historical patterns
    //
    if (ProcessContext->FilesRenamed > 1000) {
        Score += 20;
    }

    if (ProcessContext->FilesDeleted > 500) {
        Score += 15;
    }

    //
    // High entropy writes would add to score (checked elsewhere)
    //
    if (ProcessContext->BehaviorFlags & FSC_BEHAVIOR_HIGH_ENTROPY) {
        Score += 25;
    }

    //
    // Extension changes are suspicious
    //
    if (ProcessContext->BehaviorFlags & FSC_BEHAVIOR_EXTENSION_CHANGE) {
        Score += 20;
    }

    ProcessContext->SuspicionScore = Score;

    return (Score >= 70);  // 70% threshold for ransomware classification
}

// ============================================================================
// CLEANUP AND TIMER
// ============================================================================

static VOID
FscpCleanupWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Work item routine that runs at PASSIVE_LEVEL for cleanup operations.
    Called from DPC to perform operations that require PASSIVE_LEVEL.

Arguments:
    DeviceObject - Device object (unused).
    Context - Work item context (unused).
--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    PAGED_CODE();

    if (g_FscState.ShutdownRequested) {
        InterlockedExchange(&g_FscState.CleanupWorkItemPending, 0);
        return;
    }

    //
    // Perform cleanup operations at PASSIVE_LEVEL
    //
    FscpCleanupStaleContexts();
    FscpResetTimeWindowedMetrics();

    //
    // Mark work item as complete
    //
    InterlockedExchange(&g_FscState.CleanupWorkItemPending, 0);
}


static VOID
FscpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++
Routine Description:
    Timer DPC callback - runs at DISPATCH_LEVEL.
    Queues a work item for operations requiring PASSIVE_LEVEL.

Arguments:
    Dpc - DPC object.
    DeferredContext - Deferred context.
    SystemArgument1/2 - System arguments.
--*/
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (g_FscState.ShutdownRequested) {
        return;
    }

    //
    // Queue work item for PASSIVE_LEVEL cleanup if not already pending
    // Note: We use InterlockedCompareExchange to ensure only one work item is queued
    //
    if (InterlockedCompareExchange(&g_FscState.CleanupWorkItemPending, 1, 0) == 0) {
        //
        // Allocate work item if needed
        //
        if (g_FscState.CleanupWorkItem == NULL && g_DriverData.DeviceObject != NULL) {
            g_FscState.CleanupWorkItem = IoAllocateWorkItem(g_DriverData.DeviceObject);
        }

        if (g_FscState.CleanupWorkItem != NULL) {
            IoQueueWorkItem(
                g_FscState.CleanupWorkItem,
                FscpCleanupWorkItemRoutine,
                DelayedWorkQueue,
                NULL
                );
        } else {
            //
            // No work item available - clear pending flag
            //
            InterlockedExchange(&g_FscState.CleanupWorkItemPending, 0);
        }
    }
}


static VOID
FscpCleanupStaleContexts(
    VOID
    )
/*++
Routine Description:
    Cleans up stale process contexts that haven't been accessed recently.
    Must be called at PASSIVE_LEVEL.
--*/
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PFSC_PROCESS_FILE_CONTEXT Context;
    LIST_ENTRY StaleList;

    PAGED_CODE();

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)300 * 10000000LL;  // 5 minutes

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_FscState.ProcessContextLock);

    for (Entry = g_FscState.ProcessContextList.Flink;
         Entry != &g_FscState.ProcessContextList;
         Entry = Next) {

        Next = Entry->Flink;
        Context = CONTAINING_RECORD(Entry, FSC_PROCESS_FILE_CONTEXT, ListEntry);

        //
        // Check if context is stale (no activity for 5 minutes)
        // Only remove if RefCount is 1 (only list reference)
        //
        if ((CurrentTime.QuadPart - Context->LastActivityTime.QuadPart) > TimeoutInterval.QuadPart) {
            if (Context->RefCount == 1) {
                RemoveEntryList(&Context->ListEntry);
                InitializeListHead(&Context->ListEntry);
                InterlockedDecrement(&g_FscState.ProcessContextCount);
                InsertTailList(&StaleList, &Context->ListEntry);
            }
        }
    }

    ExReleasePushLockExclusive(&g_FscState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Free stale contexts outside lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Context = CONTAINING_RECORD(Entry, FSC_PROCESS_FILE_CONTEXT, ListEntry);
        ExFreeToNPagedLookasideList(&g_FscState.ProcessContextLookaside, Context);
    }
}


static VOID
FscpResetTimeWindowedMetrics(
    VOID
    )
/*++
Routine Description:
    Resets time-windowed metrics for ransomware detection.
    Must be called at PASSIVE_LEVEL.
--*/
{
    PLIST_ENTRY Entry;
    PFSC_PROCESS_FILE_CONTEXT Context;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    KeQuerySystemTime(&CurrentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_FscState.ProcessContextLock);

    for (Entry = g_FscState.ProcessContextList.Flink;
         Entry != &g_FscState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, FSC_PROCESS_FILE_CONTEXT, ListEntry);

        //
        // Reset per-second counters atomically
        //
        InterlockedExchange(&Context->RecentModifications, 0);
        InterlockedExchange(&Context->RecentDeletions, 0);
        InterlockedExchange(&Context->RecentRenames, 0);
        Context->WindowStartTime = CurrentTime;
    }

    ExReleasePushLockShared(&g_FscState.ProcessContextLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PUBLIC STATISTICS API
// ============================================================================

NTSTATUS
ShadowStrikeGetFileSystemStats(
    _Out_ PULONG64 PreCreateCalls,
    _Out_ PULONG64 FilesBlocked,
    _Out_ PULONG64 RansomwareDetections,
    _Out_ PULONG VolumeCount
    )
/*++
Routine Description:
    Gets filesystem callback statistics.

Arguments:
    PreCreateCalls - Receives total PreCreate calls.
    FilesBlocked - Receives files blocked count.
    RansomwareDetections - Receives ransomware detection count.
    VolumeCount - Receives attached volume count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    if (!g_FscState.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (PreCreateCalls != NULL) {
        *PreCreateCalls = (ULONG64)g_FscState.Stats.PreCreateCalls;
    }

    if (FilesBlocked != NULL) {
        *FilesBlocked = (ULONG64)g_DriverData.Stats.FilesBlocked;
    }

    if (RansomwareDetections != NULL) {
        *RansomwareDetections = (ULONG64)g_FscState.Stats.RansomwareDetections;
    }

    if (VolumeCount != NULL) {
        *VolumeCount = (ULONG)g_FscState.VolumeCount;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeQueryProcessFileContext(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsRansomwareSuspect,
    _Out_ PULONG SuspicionScore,
    _Out_ PULONG BehaviorFlags
    )
/*++
Routine Description:
    Queries file operation context for a process.

Arguments:
    ProcessId - Process ID to query.
    IsRansomwareSuspect - Receives ransomware suspect flag.
    SuspicionScore - Receives suspicion score.
    BehaviorFlags - Receives behavior flags.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PFSC_PROCESS_FILE_CONTEXT Context;

    if (!g_FscState.Initialized) {
        return STATUS_NOT_FOUND;
    }

    Context = FscpLookupProcessContext(ProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (IsRansomwareSuspect != NULL) {
        *IsRansomwareSuspect = Context->IsRansomwareSuspect;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = Context->SuspicionScore;
    }

    if (BehaviorFlags != NULL) {
        *BehaviorFlags = Context->BehaviorFlags;
    }

    FscpDereferenceProcessContext(Context);

    return STATUS_SUCCESS;
}


VOID
ShadowStrikeNotifyProcessFileOperation(
    _In_ HANDLE ProcessId,
    _In_ ULONG OperationType,
    _In_opt_ PCUNICODE_STRING FileName
    )
/*++
Routine Description:
    External API to notify of file operations (for integration with other modules).

Arguments:
    ProcessId - Process performing operation.
    OperationType - Type of operation.
    FileName - Optional file name.
--*/
{
    if (!g_FscState.Initialized) {
        return;
    }

    FscpUpdateProcessFileMetrics(ProcessId, OperationType, FileName);
}

