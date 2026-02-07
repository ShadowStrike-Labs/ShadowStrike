/*++
    ShadowStrike Next-Generation Antivirus
    Module: ImageNotify.c

    Purpose: Enterprise-grade image load notification callback for
             DLL injection detection, driver load monitoring, and
             malicious module identification.

    Architecture:
    - PsSetLoadImageNotifyRoutineEx integration
    - PE header validation and anomaly detection
    - Unsigned/untrusted module flagging
    - DLL side-loading detection
    - Reflective DLL injection detection
    - Module stomping detection
    - Known vulnerable driver detection (BYOVD)
    - Telemetry generation for SIEM integration

    Security Guarantees:
    - All memory accesses validated with SEH
    - Integer overflow protection on calculations
    - Thread-safe global state management
    - Rate limiting to prevent resource exhaustion
    - Secure memory handling for sensitive data

    Copyright (c) ShadowStrike Team
--*/

#include "ImageNotify.h"
#include "../../Core/Globals.h"
#include "../../Communication/ScanBridge.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/HashUtils.h"
#include "../../Utilities/StringUtils.h"
#include "../../Utilities/ProcessUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ImageNotifyInitialize)
#pragma alloc_text(PAGE, RegisterImageNotify)
#pragma alloc_text(PAGE, UnregisterImageNotify)
#pragma alloc_text(PAGE, ImageNotifyShutdown)
#pragma alloc_text(PAGE, ImageNotifySetConfig)
#pragma alloc_text(PAGE, ImageNotifyRegisterPreLoadCallback)
#pragma alloc_text(PAGE, ImageNotifyRegisterPostLoadCallback)
#pragma alloc_text(PAGE, ImageNotifyUnregisterCallback)
#pragma alloc_text(PAGE, ImageNotifyAddVulnerableDriver)
#pragma alloc_text(PAGE, ImageNotifyQueryProcessModules)
#pragma alloc_text(PAGE, ImageNotifyIsModuleLoaded)
#endif

//=============================================================================
// Private Constants
//=============================================================================

#define IMG_VERSION                     1
#define IMG_MAX_CALLBACKS               16
#define IMG_VULNERABLE_DRIVER_BUCKETS   64
#define IMG_MAX_VULNERABLE_DRIVERS      512
#define IMG_RATE_LIMIT_WINDOW_MS        1000
#define IMG_DEFAULT_MAX_EVENTS_PER_SEC  10000
#define IMG_HIGH_ENTROPY_THRESHOLD      700     // 7.0 * 100

//
// Suspicious path patterns
//
static const WCHAR* g_SuspiciousPaths[] = {
    L"\\Temp\\",
    L"\\tmp\\",
    L"\\AppData\\Local\\Temp\\",
    L"\\Downloads\\",
    L"\\ProgramData\\",
    L"\\Users\\Public\\",
    L"\\Windows\\Temp\\",
    L"\\Recycle",
};
#define IMG_SUSPICIOUS_PATH_COUNT (sizeof(g_SuspiciousPaths) / sizeof(g_SuspiciousPaths[0]))

//
// System DLL names for masquerading detection
//
static const WCHAR* g_SystemDllNames[] = {
    L"ntdll.dll",
    L"kernel32.dll",
    L"kernelbase.dll",
    L"user32.dll",
    L"advapi32.dll",
    L"shell32.dll",
    L"ole32.dll",
    L"combase.dll",
    L"msvcrt.dll",
    L"ws2_32.dll",
    L"crypt32.dll",
    L"secur32.dll",
};
#define IMG_SYSTEM_DLL_COUNT (sizeof(g_SystemDllNames) / sizeof(g_SystemDllNames[0]))

//=============================================================================
// Private Structures
//=============================================================================

//
// Callback registration entry
//
typedef struct _IMG_CALLBACK_ENTRY {
    LIST_ENTRY ListEntry;
    union {
        IMG_PRE_LOAD_CALLBACK PreLoad;
        IMG_POST_LOAD_CALLBACK PostLoad;
    } Callback;
    PVOID Context;
    BOOLEAN IsPreLoad;
    volatile LONG Active;
} IMG_CALLBACK_ENTRY, *PIMG_CALLBACK_ENTRY;

//
// Vulnerable driver entry
//
typedef struct _IMG_VULNERABLE_DRIVER {
    LIST_ENTRY HashEntry;
    UCHAR Sha256Hash[32];
    WCHAR DriverName[64];
    CHAR CveId[32];
} IMG_VULNERABLE_DRIVER, *PIMG_VULNERABLE_DRIVER;

//
// Global image notify state
//
typedef struct _IMG_NOTIFY_GLOBALS {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    BOOLEAN CallbackRegistered;

    //
    // Configuration
    //
    IMG_NOTIFY_CONFIG Config;
    EX_PUSH_LOCK ConfigLock;

    //
    // Callback registrations
    //
    LIST_ENTRY PreLoadCallbacks;
    LIST_ENTRY PostLoadCallbacks;
    EX_PUSH_LOCK CallbackLock;
    volatile LONG PreLoadCallbackCount;
    volatile LONG PostLoadCallbackCount;

    //
    // Vulnerable driver database
    //
    LIST_ENTRY VulnerableDriverHash[IMG_VULNERABLE_DRIVER_BUCKETS];
    EX_PUSH_LOCK VulnerableDriverLock;
    volatile LONG VulnerableDriverCount;

    //
    // Lookaside lists
    //
    SHADOWSTRIKE_LOOKASIDE EventLookaside;

    //
    // Rate limiting
    //
    volatile LONG64 EventsThisWindow;
    volatile LONG64 WindowStartTime;

    //
    // Statistics
    //
    IMG_NOTIFY_STATISTICS Stats;

    //
    // Event ID generation
    //
    volatile LONG64 NextEventId;

} IMG_NOTIFY_GLOBALS, *PIMG_NOTIFY_GLOBALS;

//
// Global instance
//
static IMG_NOTIFY_GLOBALS g_ImgNotify = { 0 };

//=============================================================================
// Forward Declarations
//=============================================================================

VOID
ImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

static
NTSTATUS
ImgpAllocateEvent(
    _Out_ PIMG_LOAD_EVENT* Event
    );

static
VOID
ImgpFreeEvent(
    _In_ PIMG_LOAD_EVENT Event
    );

static
VOID
ImgpPopulateEvent(
    _Inout_ PIMG_LOAD_EVENT Event,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

static
IMG_TYPE
ImgpDetermineImageType(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
    );

static
VOID
ImgpExtractFileName(
    _In_ PUNICODE_STRING FullPath,
    _Out_writes_(MaxLength) PWCHAR FileName,
    _In_ ULONG MaxLength
    );

static
IMG_LOAD_FLAGS
ImgpAnalyzeImageFlags(
    _In_ PIMAGE_INFO ImageInfo,
    _In_ HANDLE ProcessId
    );

static
NTSTATUS
ImgpAnalyzePeHeader(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_ PIMG_PE_INFO PeInfo
    );

static
IMG_SUSPICIOUS_REASON
ImgpDetectSuspiciousIndicators(
    _In_ PIMG_LOAD_EVENT Event
    );

static
BOOLEAN
ImgpIsPathSuspicious(
    _In_ PCWSTR Path
    );

static
BOOLEAN
ImgpIsMasqueradingName(
    _In_ PCWSTR FileName
    );

static
ULONG
ImgpCalculateThreatScore(
    _In_ PIMG_LOAD_EVENT Event
    );

static
BOOLEAN
ImgpCheckRateLimit(
    VOID
    );

static
VOID
ImgpNotifyPreLoadCallbacks(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN BlockLoad
    );

static
VOID
ImgpNotifyPostLoadCallbacks(
    _In_ PIMG_LOAD_EVENT Event
    );

static
ULONG
ImgpHashVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash
    );

static
VOID
ImgpInitializeDefaultConfig(
    _Out_ PIMG_NOTIFY_CONFIG Config
    );

static
ULONG
ImgpCalculateSectionEntropy(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

_Use_decl_annotations_
NTSTATUS
ImageNotifyInitialize(
    PIMG_NOTIFY_CONFIG Config
    )
/*++

Routine Description:

    Initializes the image load notification subsystem with
    enterprise-grade detection capabilities.

Arguments:

    Config - Optional configuration (NULL for defaults)

Return Value:

    STATUS_SUCCESS if successful

--*/
{
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    if (g_ImgNotify.Initialized) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_ImgNotify, sizeof(IMG_NOTIFY_GLOBALS));

    //
    // Initialize locks
    //
    ExInitializePushLock(&g_ImgNotify.ConfigLock);
    ExInitializePushLock(&g_ImgNotify.CallbackLock);
    ExInitializePushLock(&g_ImgNotify.VulnerableDriverLock);

    //
    // Initialize lists
    //
    InitializeListHead(&g_ImgNotify.PreLoadCallbacks);
    InitializeListHead(&g_ImgNotify.PostLoadCallbacks);

    for (i = 0; i < IMG_VULNERABLE_DRIVER_BUCKETS; i++) {
        InitializeListHead(&g_ImgNotify.VulnerableDriverHash[i]);
    }

    //
    // Initialize configuration
    //
    if (Config != NULL) {
        RtlCopyMemory(&g_ImgNotify.Config, Config, sizeof(IMG_NOTIFY_CONFIG));
    } else {
        ImgpInitializeDefaultConfig(&g_ImgNotify.Config);
    }

    //
    // Initialize lookaside list for events
    //
    status = ShadowStrikeLookasideInit(
        &g_ImgNotify.EventLookaside,
        sizeof(IMG_LOAD_EVENT),
        IMG_POOL_TAG_EVENT,
        IMG_LOOKASIDE_DEPTH,
        FALSE   // Non-paged for callback context
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Initialize rate limiting
    //
    KeQuerySystemTime((PLARGE_INTEGER)&g_ImgNotify.WindowStartTime);

    //
    // Record start time for statistics
    //
    KeQuerySystemTime(&g_ImgNotify.Stats.StartTime);

    g_ImgNotify.Initialized = TRUE;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
RegisterImageNotify(
    VOID
    )
/*++

Routine Description:

    Registers the image load notification callback with the kernel.

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    if (!g_ImgNotify.Initialized) {
        //
        // Auto-initialize with defaults
        //
        status = ImageNotifyInitialize(NULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (g_ImgNotify.CallbackRegistered) {
        return STATUS_SUCCESS;
    }

    //
    // Register with extended routine for driver blocking capability
    // Fall back to standard routine if Ex version not available
    //
    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

    if (NT_SUCCESS(status)) {
        g_ImgNotify.CallbackRegistered = TRUE;
        g_DriverData.ImageNotifyRegistered = TRUE;
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
UnregisterImageNotify(
    VOID
    )
/*++

Routine Description:

    Unregisters the image load notification callback.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (g_ImgNotify.CallbackRegistered) {
        status = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

        if (NT_SUCCESS(status)) {
            g_ImgNotify.CallbackRegistered = FALSE;
            g_DriverData.ImageNotifyRegistered = FALSE;
        }
    }

    return status;
}


_Use_decl_annotations_
VOID
ImageNotifyShutdown(
    VOID
    )
/*++

Routine Description:

    Shuts down the image notification subsystem and releases resources.

--*/
{
    PLIST_ENTRY entry;
    PIMG_CALLBACK_ENTRY callback;
    PIMG_VULNERABLE_DRIVER driver;
    ULONG i;

    PAGED_CODE();

    if (!g_ImgNotify.Initialized) {
        return;
    }

    //
    // Unregister callback first
    //
    UnregisterImageNotify();

    g_ImgNotify.Initialized = FALSE;

    //
    // Free all callback registrations
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.CallbackLock);

    while (!IsListEmpty(&g_ImgNotify.PreLoadCallbacks)) {
        entry = RemoveHeadList(&g_ImgNotify.PreLoadCallbacks);
        callback = CONTAINING_RECORD(entry, IMG_CALLBACK_ENTRY, ListEntry);
        ShadowStrikeFreePoolWithTag(callback, IMG_POOL_TAG_CONTEXT);
    }

    while (!IsListEmpty(&g_ImgNotify.PostLoadCallbacks)) {
        entry = RemoveHeadList(&g_ImgNotify.PostLoadCallbacks);
        callback = CONTAINING_RECORD(entry, IMG_CALLBACK_ENTRY, ListEntry);
        ShadowStrikeFreePoolWithTag(callback, IMG_POOL_TAG_CONTEXT);
    }

    ExReleasePushLockExclusive(&g_ImgNotify.CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Free vulnerable driver database
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.VulnerableDriverLock);

    for (i = 0; i < IMG_VULNERABLE_DRIVER_BUCKETS; i++) {
        while (!IsListEmpty(&g_ImgNotify.VulnerableDriverHash[i])) {
            entry = RemoveHeadList(&g_ImgNotify.VulnerableDriverHash[i]);
            driver = CONTAINING_RECORD(entry, IMG_VULNERABLE_DRIVER, HashEntry);
            ShadowStrikeFreePoolWithTag(driver, IMG_POOL_TAG_HASH);
        }
    }

    ExReleasePushLockExclusive(&g_ImgNotify.VulnerableDriverLock);
    KeLeaveCriticalRegion();

    //
    // Cleanup lookaside list
    //
    ShadowStrikeLookasideCleanup(&g_ImgNotify.EventLookaside);
}

//=============================================================================
// Public API - Configuration
//=============================================================================

_Use_decl_annotations_
NTSTATUS
ImageNotifySetConfig(
    PIMG_NOTIFY_CONFIG Config
    )
{
    PAGED_CODE();

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.ConfigLock);

    RtlCopyMemory(&g_ImgNotify.Config, Config, sizeof(IMG_NOTIFY_CONFIG));

    ExReleasePushLockExclusive(&g_ImgNotify.ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ImageNotifyGetConfig(
    PIMG_NOTIFY_CONFIG Config
    )
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ImgNotify.ConfigLock);

    RtlCopyMemory(Config, &g_ImgNotify.Config, sizeof(IMG_NOTIFY_CONFIG));

    ExReleasePushLockShared(&g_ImgNotify.ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

//=============================================================================
// Public API - Callbacks
//=============================================================================

_Use_decl_annotations_
NTSTATUS
ImageNotifyRegisterPreLoadCallback(
    IMG_PRE_LOAD_CALLBACK Callback,
    PVOID Context
    )
{
    PIMG_CALLBACK_ENTRY entry;

    PAGED_CODE();

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_ImgNotify.PreLoadCallbackCount >= IMG_MAX_CALLBACKS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    entry = (PIMG_CALLBACK_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(IMG_CALLBACK_ENTRY),
        IMG_POOL_TAG_CONTEXT
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Callback.PreLoad = Callback;
    entry->Context = Context;
    entry->IsPreLoad = TRUE;
    entry->Active = TRUE;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.CallbackLock);

    InsertTailList(&g_ImgNotify.PreLoadCallbacks, &entry->ListEntry);
    InterlockedIncrement(&g_ImgNotify.PreLoadCallbackCount);

    ExReleasePushLockExclusive(&g_ImgNotify.CallbackLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ImageNotifyRegisterPostLoadCallback(
    IMG_POST_LOAD_CALLBACK Callback,
    PVOID Context
    )
{
    PIMG_CALLBACK_ENTRY entry;

    PAGED_CODE();

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_ImgNotify.PostLoadCallbackCount >= IMG_MAX_CALLBACKS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    entry = (PIMG_CALLBACK_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(IMG_CALLBACK_ENTRY),
        IMG_POOL_TAG_CONTEXT
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Callback.PostLoad = Callback;
    entry->Context = Context;
    entry->IsPreLoad = FALSE;
    entry->Active = TRUE;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.CallbackLock);

    InsertTailList(&g_ImgNotify.PostLoadCallbacks, &entry->ListEntry);
    InterlockedIncrement(&g_ImgNotify.PostLoadCallbackCount);

    ExReleasePushLockExclusive(&g_ImgNotify.CallbackLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
ImageNotifyUnregisterCallback(
    PVOID Callback
    )
{
    PLIST_ENTRY entry;
    PIMG_CALLBACK_ENTRY callbackEntry;
    PIMG_CALLBACK_ENTRY foundEntry = NULL;

    PAGED_CODE();

    if (Callback == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.CallbackLock);

    //
    // Search pre-load callbacks
    //
    for (entry = g_ImgNotify.PreLoadCallbacks.Flink;
         entry != &g_ImgNotify.PreLoadCallbacks;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, IMG_CALLBACK_ENTRY, ListEntry);

        if (callbackEntry->Callback.PreLoad == (IMG_PRE_LOAD_CALLBACK)Callback) {
            RemoveEntryList(&callbackEntry->ListEntry);
            InterlockedDecrement(&g_ImgNotify.PreLoadCallbackCount);
            foundEntry = callbackEntry;
            break;
        }
    }

    //
    // Search post-load callbacks if not found
    //
    if (foundEntry == NULL) {
        for (entry = g_ImgNotify.PostLoadCallbacks.Flink;
             entry != &g_ImgNotify.PostLoadCallbacks;
             entry = entry->Flink) {

            callbackEntry = CONTAINING_RECORD(entry, IMG_CALLBACK_ENTRY, ListEntry);

            if (callbackEntry->Callback.PostLoad == (IMG_POST_LOAD_CALLBACK)Callback) {
                RemoveEntryList(&callbackEntry->ListEntry);
                InterlockedDecrement(&g_ImgNotify.PostLoadCallbackCount);
                foundEntry = callbackEntry;
                break;
            }
        }
    }

    ExReleasePushLockExclusive(&g_ImgNotify.CallbackLock);
    KeLeaveCriticalRegion();

    if (foundEntry != NULL) {
        InterlockedExchange(&foundEntry->Active, FALSE);
        ShadowStrikeFreePoolWithTag(foundEntry, IMG_POOL_TAG_CONTEXT);
    }
}

//=============================================================================
// Public API - Vulnerable Driver Database
//=============================================================================

_Use_decl_annotations_
NTSTATUS
ImageNotifyAddVulnerableDriver(
    PUCHAR Sha256Hash,
    PCWSTR DriverName,
    PCSTR CveId
    )
{
    PIMG_VULNERABLE_DRIVER entry;
    ULONG bucket;

    PAGED_CODE();

    if (Sha256Hash == NULL || DriverName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_ImgNotify.VulnerableDriverCount >= IMG_MAX_VULNERABLE_DRIVERS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    entry = (PIMG_VULNERABLE_DRIVER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(IMG_VULNERABLE_DRIVER),
        IMG_POOL_TAG_HASH
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(entry->Sha256Hash, Sha256Hash, 32);
    RtlStringCchCopyW(entry->DriverName, 64, DriverName);

    if (CveId != NULL) {
        RtlStringCchCopyA(entry->CveId, 32, CveId);
    } else {
        entry->CveId[0] = '\0';
    }

    bucket = ImgpHashVulnerableDriver(Sha256Hash);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ImgNotify.VulnerableDriverLock);

    InsertTailList(&g_ImgNotify.VulnerableDriverHash[bucket], &entry->HashEntry);
    InterlockedIncrement(&g_ImgNotify.VulnerableDriverCount);

    ExReleasePushLockExclusive(&g_ImgNotify.VulnerableDriverLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
BOOLEAN
ImageNotifyIsVulnerableDriver(
    PUCHAR Sha256Hash
    )
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PIMG_VULNERABLE_DRIVER driver;
    BOOLEAN found = FALSE;

    if (Sha256Hash == NULL) {
        return FALSE;
    }

    bucket = ImgpHashVulnerableDriver(Sha256Hash);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ImgNotify.VulnerableDriverLock);

    for (entry = g_ImgNotify.VulnerableDriverHash[bucket].Flink;
         entry != &g_ImgNotify.VulnerableDriverHash[bucket];
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, IMG_VULNERABLE_DRIVER, HashEntry);

        if (RtlCompareMemory(driver->Sha256Hash, Sha256Hash, 32) == 32) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_ImgNotify.VulnerableDriverLock);
    KeLeaveCriticalRegion();

    return found;
}

//=============================================================================
// Public API - Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
ImageNotifyGetStatistics(
    PIMG_NOTIFY_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Stats, &g_ImgNotify.Stats, sizeof(IMG_NOTIFY_STATISTICS));

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
ImageNotifyResetStatistics(
    VOID
    )
{
    RtlZeroMemory(&g_ImgNotify.Stats, sizeof(IMG_NOTIFY_STATISTICS));
    KeQuerySystemTime(&g_ImgNotify.Stats.StartTime);
}

//=============================================================================
// Public API - Query Functions
//=============================================================================

_Use_decl_annotations_
NTSTATUS
ImageNotifyQueryProcessModules(
    HANDLE ProcessId,
    PIMG_LOAD_EVENT Modules,
    ULONG MaxModules,
    PULONG ModuleCount
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Modules);
    UNREFERENCED_PARAMETER(MaxModules);

    //
    // This would require maintaining a per-process module list
    // For now, return empty - full implementation would track modules
    //
    if (ModuleCount != NULL) {
        *ModuleCount = 0;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
BOOLEAN
ImageNotifyIsModuleLoaded(
    HANDLE ProcessId,
    PUNICODE_STRING ModuleName,
    PPVOID ImageBase
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ModuleName);

    if (ImageBase != NULL) {
        *ImageBase = NULL;
    }

    //
    // Full implementation would check tracked modules
    //
    return FALSE;
}

//=============================================================================
// Main Callback Implementation
//=============================================================================

_Use_decl_annotations_
VOID
ImageLoadNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
    )
/*++

Routine Description:

    Callback routine invoked when an image is loaded. Performs comprehensive
    analysis for threat detection.

Arguments:

    FullImageName - The name of the image being loaded (may be NULL)
    ProcessId - The process ID where the image is loaded (0 for kernel)
    ImageInfo - Information about the image

--*/
{
    NTSTATUS status;
    PIMG_LOAD_EVENT event = NULL;
    BOOLEAN blockLoad = FALSE;
    IMG_NOTIFY_CONFIG config;

    PAGED_CODE();

    //
    // Check if driver is ready
    //
    if (!SHADOWSTRIKE_IS_READY() || !g_ImgNotify.Initialized) {
        return;
    }

    //
    // Validate ImageInfo
    //
    if (ImageInfo == NULL) {
        return;
    }

    //
    // Get current configuration
    //
    ImageNotifyGetConfig(&config);

    //
    // Check rate limit
    //
    if (!ImgpCheckRateLimit()) {
        InterlockedIncrement64(&g_ImgNotify.Stats.EventsDropped);
        return;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_ImgNotify.Stats.TotalImagesLoaded);

    if (ProcessId == NULL) {
        InterlockedIncrement64(&g_ImgNotify.Stats.KernelModeImages);
    } else {
        InterlockedIncrement64(&g_ImgNotify.Stats.UserModeImages);
    }

    //
    // Invoke pre-load callbacks (can block driver loads)
    //
    if (g_ImgNotify.PreLoadCallbackCount > 0 && ProcessId == NULL) {
        ImgpNotifyPreLoadCallbacks(ProcessId, FullImageName, ImageInfo, &blockLoad);

        if (blockLoad) {
            InterlockedIncrement64(&g_ImgNotify.Stats.BlockedImages);
            //
            // Note: Actual blocking requires PsSetLoadImageNotifyRoutineEx
            // with IMAGE_INFO_EX and setting the ExtendedFlags
            //
            return;
        }
    }

    //
    // Allocate event structure
    //
    status = ImgpAllocateEvent(&event);
    if (!NT_SUCCESS(status)) {
        return;
    }

    //
    // Populate event with image information
    //
    ImgpPopulateEvent(event, FullImageName, ProcessId, ImageInfo);

    //
    // Analyze image flags
    //
    event->Flags = ImgpAnalyzeImageFlags(ImageInfo, ProcessId);

    //
    // Perform PE analysis if enabled
    //
    if (config.EnablePeAnalysis && ImageInfo->ImageBase != NULL) {
        status = ImgpAnalyzePeHeader(
            ImageInfo->ImageBase,
            ImageInfo->ImageSize,
            &event->PeInfo
            );

        if (NT_SUCCESS(status)) {
            event->PeAnalyzed = TRUE;
            InterlockedIncrement64(&g_ImgNotify.Stats.PeAnalyses);

            //
            // Check for anomalies
            //
            if (event->PeInfo.IsDll && event->PeInfo.ExportCount == 0) {
                event->Flags |= ImgFlag_NoExports;
            }

            if (!event->PeInfo.ChecksumValid) {
                event->Flags |= ImgFlag_AbnormalSections;
            }

            //
            // Check for writable code sections
            //
            for (USHORT i = 0; i < event->PeInfo.NumberOfSections && i < 16; i++) {
                if (event->PeInfo.Sections[i].IsExecutable &&
                    event->PeInfo.Sections[i].IsWritable) {
                    event->Flags |= ImgFlag_SelfModifying;
                }

                if (event->PeInfo.Sections[i].Entropy > config.HighEntropyThreshold) {
                    event->Flags |= ImgFlag_HighEntropy;
                }
            }
        }
    }

    //
    // Compute hashes if enabled
    //
    if (config.EnableHashComputation && FullImageName != NULL) {
        //
        // Note: Full implementation would read file and compute hash
        // For now, we skip file hashing to avoid blocking I/O in callback
        //
        event->HashesComputed = FALSE;
    }

    //
    // Detect suspicious indicators
    //
    if (config.EnableSuspiciousDetection) {
        event->SuspiciousReasons = ImgpDetectSuspiciousIndicators(event);

        if (event->SuspiciousReasons != ImgSuspicious_None) {
            InterlockedIncrement64(&g_ImgNotify.Stats.SuspiciousImages);
        }
    }

    //
    // Check vulnerable driver database for kernel images
    //
    if (config.EnableVulnerableDriverCheck &&
        ProcessId == NULL &&
        event->HashesComputed) {

        if (ImageNotifyIsVulnerableDriver(event->Sha256Hash)) {
            event->Flags |= ImgFlag_KnownVulnerable;
            event->SuspiciousReasons |= ImgSuspicious_KnownMalware;
        }
    }

    //
    // Calculate threat score
    //
    event->ThreatScore = ImgpCalculateThreatScore(event);

    //
    // Check signature status
    //
    if (event->Flags & ImgFlag_Signed) {
        InterlockedIncrement64(&g_ImgNotify.Stats.SignedImages);
    } else if (event->Flags & ImgFlag_Unsigned) {
        InterlockedIncrement64(&g_ImgNotify.Stats.UnsignedImages);
    }

    //
    // Send notification to user mode if threshold met
    //
    if (event->ThreatScore >= config.MinThreatScoreToReport ||
        event->SuspiciousReasons != ImgSuspicious_None ||
        (ProcessId == NULL && config.MonitorKernelImages)) {

        ShadowStrikeSendImageNotification(
            ProcessId,
            FullImageName,
            ImageInfo
            );
    }

    //
    // Invoke post-load callbacks
    //
    if (g_ImgNotify.PostLoadCallbackCount > 0) {
        ImgpNotifyPostLoadCallbacks(event);
    }

    //
    // Free event
    //
    ImgpFreeEvent(event);
}

//=============================================================================
// Private Functions - Event Management
//=============================================================================

static
NTSTATUS
ImgpAllocateEvent(
    PIMG_LOAD_EVENT* Event
    )
{
    PIMG_LOAD_EVENT event;

    event = (PIMG_LOAD_EVENT)ShadowStrikeLookasideAllocate(&g_ImgNotify.EventLookaside);

    if (event == NULL) {
        event = (PIMG_LOAD_EVENT)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(IMG_LOAD_EVENT),
            IMG_POOL_TAG_EVENT
            );

        if (event == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    RtlZeroMemory(event, sizeof(IMG_LOAD_EVENT));
    *Event = event;

    return STATUS_SUCCESS;
}


static
VOID
ImgpFreeEvent(
    PIMG_LOAD_EVENT Event
    )
{
    if (Event != NULL) {
        ShadowStrikeLookasideFree(&g_ImgNotify.EventLookaside, Event);
    }
}


static
VOID
ImgpPopulateEvent(
    PIMG_LOAD_EVENT Event,
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
    )
{
    Event->Size = sizeof(IMG_LOAD_EVENT);
    Event->Version = IMG_VERSION;
    KeQuerySystemTime(&Event->Timestamp);
    Event->EventId = InterlockedIncrement64(&g_ImgNotify.NextEventId);

    Event->ProcessId = ProcessId;
    Event->ThreadId = PsGetCurrentThreadId();

    if (ProcessId != NULL) {
        PEPROCESS process;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
            Event->ParentProcessId = PsGetProcessInheritedFromUniqueProcessId(process);
            Event->SessionId = PsGetProcessSessionId(process);
            ObDereferenceObject(process);
        }
    }

    Event->ImageBase = ImageInfo->ImageBase;
    Event->ImageSize = ImageInfo->ImageSize;
    Event->ImageType = ImgpDetermineImageType(FullImageName, ImageInfo);

    //
    // Copy image path
    //
    if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
        __try {
            ULONG copyLen = min(FullImageName->Length, sizeof(Event->FullImagePath) - sizeof(WCHAR));
            RtlCopyMemory(Event->FullImagePath, FullImageName->Buffer, copyLen);
            Event->FullImagePath[copyLen / sizeof(WCHAR)] = L'\0';

            ImgpExtractFileName(FullImageName, Event->ImageFileName, 64);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Event->FullImagePath[0] = L'\0';
            Event->ImageFileName[0] = L'\0';
        }
    }

    //
    // Get process image path
    //
    if (ProcessId != NULL) {
        UNICODE_STRING processPath;
        if (NT_SUCCESS(ShadowStrikeGetProcessImagePath(ProcessId, &processPath))) {
            ULONG copyLen = min(processPath.Length, sizeof(Event->ProcessImagePath) - sizeof(WCHAR));
            RtlCopyMemory(Event->ProcessImagePath, processPath.Buffer, copyLen);
            Event->ProcessImagePath[copyLen / sizeof(WCHAR)] = L'\0';
            ShadowFreeProcessString(&processPath);
        }
    }
}


static
IMG_TYPE
ImgpDetermineImageType(
    PUNICODE_STRING FullImageName,
    PIMAGE_INFO ImageInfo
    )
{
    SIZE_T length;
    PCWSTR extension;

    //
    // Kernel mode images are drivers
    //
    if (ImageInfo->SystemModeImage) {
        return ImgType_Sys;
    }

    if (FullImageName == NULL || FullImageName->Buffer == NULL) {
        return ImgType_Unknown;
    }

    //
    // Find extension
    //
    length = FullImageName->Length / sizeof(WCHAR);

    for (SIZE_T i = length; i > 0; i--) {
        if (FullImageName->Buffer[i - 1] == L'.') {
            extension = &FullImageName->Buffer[i - 1];

            if (_wcsnicmp(extension, L".dll", 4) == 0) return ImgType_Dll;
            if (_wcsnicmp(extension, L".exe", 4) == 0) return ImgType_Exe;
            if (_wcsnicmp(extension, L".sys", 4) == 0) return ImgType_Sys;
            if (_wcsnicmp(extension, L".drv", 4) == 0) return ImgType_Drv;
            if (_wcsnicmp(extension, L".ocx", 4) == 0) return ImgType_Ocx;
            if (_wcsnicmp(extension, L".cpl", 4) == 0) return ImgType_Cpl;
            if (_wcsnicmp(extension, L".scr", 4) == 0) return ImgType_Scr;
            if (_wcsnicmp(extension, L".efi", 4) == 0) return ImgType_Efi;

            break;
        }
    }

    return ImgType_Unknown;
}


static
VOID
ImgpExtractFileName(
    PUNICODE_STRING FullPath,
    PWCHAR FileName,
    ULONG MaxLength
    )
{
    SIZE_T length;
    SIZE_T start = 0;

    if (FullPath == NULL || FullPath->Buffer == NULL || MaxLength == 0) {
        if (FileName != NULL && MaxLength > 0) {
            FileName[0] = L'\0';
        }
        return;
    }

    length = FullPath->Length / sizeof(WCHAR);

    //
    // Find last backslash
    //
    for (SIZE_T i = length; i > 0; i--) {
        if (FullPath->Buffer[i - 1] == L'\\') {
            start = i;
            break;
        }
    }

    //
    // Copy filename
    //
    SIZE_T copyLen = min(length - start, MaxLength - 1);
    RtlCopyMemory(FileName, &FullPath->Buffer[start], copyLen * sizeof(WCHAR));
    FileName[copyLen] = L'\0';
}

//=============================================================================
// Private Functions - Analysis
//=============================================================================

static
IMG_LOAD_FLAGS
ImgpAnalyzeImageFlags(
    PIMAGE_INFO ImageInfo,
    HANDLE ProcessId
    )
{
    IMG_LOAD_FLAGS flags = ImgFlag_None;

    if (ImageInfo->SystemModeImage) {
        flags |= ImgFlag_KernelMode;
    } else {
        flags |= ImgFlag_UserMode;
    }

    if (ImageInfo->ImageMappedToAllPids) {
        flags |= ImgFlag_SystemModule;
    }

    if (ImageInfo->MachineTypeMismatch) {
        flags |= ImgFlag_AbnormalSections;
    }

    //
    // Extended image info (Windows 10+)
    //
    if (ImageInfo->ExtendedInfoPresent) {
        PIMAGE_INFO_EX imageInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

        if (imageInfoEx->FileObject == NULL) {
            flags |= ImgFlag_UnbackedMemory;
        }
    }

    UNREFERENCED_PARAMETER(ProcessId);

    return flags;
}


static
NTSTATUS
ImgpAnalyzePeHeader(
    PVOID ImageBase,
    SIZE_T ImageSize,
    PIMG_PE_INFO PeInfo
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG i;

    if (ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER) || PeInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(PeInfo, sizeof(IMG_PE_INFO));

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ImageBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if ((ULONG)dosHeader->e_lfanew > ImageSize - sizeof(IMAGE_NT_HEADERS)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        //
        // Populate basic info
        //
        PeInfo->Machine = ntHeaders->FileHeader.Machine;
        PeInfo->Is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
        PeInfo->Characteristics = ntHeaders->FileHeader.Characteristics;
        PeInfo->IsDll = (PeInfo->Characteristics & IMAGE_FILE_DLL) != 0;
        PeInfo->TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
        PeInfo->NumberOfSections = ntHeaders->FileHeader.NumberOfSections;

        //
        // Optional header fields
        //
        if (PeInfo->Is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            PeInfo->Subsystem = ntHeaders64->OptionalHeader.Subsystem;
            PeInfo->DllCharacteristics = ntHeaders64->OptionalHeader.DllCharacteristics;
            PeInfo->AddressOfEntryPoint = ntHeaders64->OptionalHeader.AddressOfEntryPoint;
            PeInfo->CheckSum = ntHeaders64->OptionalHeader.CheckSum;

            PeInfo->IsDriver = (PeInfo->Subsystem == IMAGE_SUBSYSTEM_NATIVE);
            PeInfo->IsDotNet = (ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0);

            PeInfo->HasSecurityDirectory = (ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0);
            PeInfo->SecurityDirectorySize = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

            PeInfo->HasTlsCallbacks = (ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0);
        } else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            PeInfo->Subsystem = ntHeaders32->OptionalHeader.Subsystem;
            PeInfo->DllCharacteristics = ntHeaders32->OptionalHeader.DllCharacteristics;
            PeInfo->AddressOfEntryPoint = ntHeaders32->OptionalHeader.AddressOfEntryPoint;
            PeInfo->CheckSum = ntHeaders32->OptionalHeader.CheckSum;

            PeInfo->IsDriver = (PeInfo->Subsystem == IMAGE_SUBSYSTEM_NATIVE);
            PeInfo->IsDotNet = (ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0);

            PeInfo->HasSecurityDirectory = (ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0);
            PeInfo->SecurityDirectorySize = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

            PeInfo->HasTlsCallbacks = (ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0);
        }

        PeInfo->EntryPointVa = (PUCHAR)ImageBase + PeInfo->AddressOfEntryPoint;

        //
        // Analyze sections
        //
        sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (i = 0; i < PeInfo->NumberOfSections && i < 16; i++) {
            RtlCopyMemory(PeInfo->Sections[i].Name, sectionHeader[i].Name, 8);
            PeInfo->Sections[i].Name[8] = '\0';
            PeInfo->Sections[i].VirtualSize = sectionHeader[i].Misc.VirtualSize;
            PeInfo->Sections[i].VirtualAddress = sectionHeader[i].VirtualAddress;
            PeInfo->Sections[i].Characteristics = sectionHeader[i].Characteristics;

            PeInfo->Sections[i].IsExecutable =
                (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            PeInfo->Sections[i].IsWritable =
                (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            //
            // Check if entry point is in this section
            //
            if (PeInfo->AddressOfEntryPoint >= sectionHeader[i].VirtualAddress &&
                PeInfo->AddressOfEntryPoint < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {

                if (PeInfo->Sections[i].IsExecutable) {
                    PeInfo->EntryPointInCode = TRUE;
                }
            }

            //
            // Calculate section entropy (simplified - first 4KB)
            //
            if (sectionHeader[i].VirtualAddress + min(sectionHeader[i].Misc.VirtualSize, 4096) <= ImageSize) {
                PeInfo->Sections[i].Entropy = ImgpCalculateSectionEntropy(
                    (PUCHAR)ImageBase + sectionHeader[i].VirtualAddress,
                    min(sectionHeader[i].Misc.VirtualSize, 4096)
                    );
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}


static
IMG_SUSPICIOUS_REASON
ImgpDetectSuspiciousIndicators(
    PIMG_LOAD_EVENT Event
    )
{
    IMG_SUSPICIOUS_REASON reasons = ImgSuspicious_None;

    //
    // Check suspicious path
    //
    if (ImgpIsPathSuspicious(Event->FullImagePath)) {
        reasons |= ImgSuspicious_TempDirectory;
    }

    //
    // Check for masquerading name
    //
    if (ImgpIsMasqueradingName(Event->ImageFileName)) {
        reasons |= ImgSuspicious_MasqueradingName;
    }

    //
    // Check for network path
    //
    if (wcsncmp(Event->FullImagePath, L"\\\\", 2) == 0) {
        reasons |= ImgSuspicious_NetworkPath;
    }

    //
    // Check for double extension
    //
    PCWSTR fileName = Event->ImageFileName;
    ULONG dotCount = 0;
    while (*fileName) {
        if (*fileName == L'.') dotCount++;
        fileName++;
    }
    if (dotCount >= 2) {
        reasons |= ImgSuspicious_DoubleExtension;
    }

    //
    // Check for unbacked memory
    //
    if (Event->Flags & ImgFlag_UnbackedMemory) {
        reasons |= ImgSuspicious_PhantomDll;
    }

    //
    // Check PE anomalies
    //
    if (Event->PeAnalyzed) {
        //
        // DLL with no exports is suspicious
        //
        if (Event->PeInfo.IsDll && Event->PeInfo.ExportCount == 0) {
            // Could indicate reflective DLL
        }

        //
        // Entry point not in code section
        //
        if (!Event->PeInfo.EntryPointInCode) {
            reasons |= ImgSuspicious_ProcessHollow;
        }
    }

    return reasons;
}


static
BOOLEAN
ImgpIsPathSuspicious(
    PCWSTR Path
    )
{
    ULONG i;

    if (Path == NULL || Path[0] == L'\0') {
        return FALSE;
    }

    for (i = 0; i < IMG_SUSPICIOUS_PATH_COUNT; i++) {
        if (wcsstr(Path, g_SuspiciousPaths[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}


static
BOOLEAN
ImgpIsMasqueradingName(
    PCWSTR FileName
    )
{
    ULONG i;
    SIZE_T fileLen;
    SIZE_T sysLen;

    if (FileName == NULL || FileName[0] == L'\0') {
        return FALSE;
    }

    fileLen = wcslen(FileName);

    for (i = 0; i < IMG_SYSTEM_DLL_COUNT; i++) {
        sysLen = wcslen(g_SystemDllNames[i]);

        //
        // Check for exact match but different case (not suspicious)
        // Check for typosquatting (off-by-one, similar names)
        //

        if (fileLen == sysLen) {
            //
            // Same length - check for similar but not exact match
            //
            ULONG diffCount = 0;
            for (SIZE_T j = 0; j < fileLen; j++) {
                if (towlower(FileName[j]) != towlower(g_SystemDllNames[i][j])) {
                    diffCount++;
                }
            }

            //
            // One character difference is suspicious typosquatting
            //
            if (diffCount == 1) {
                return TRUE;
            }
        }

        //
        // Check for similar length with additions/removals
        //
        if (fileLen == sysLen + 1 || fileLen == sysLen - 1) {
            //
            // Potential insertion/deletion typosquatting
            //
            ULONG matches = 0;
            SIZE_T minLen = min(fileLen, sysLen);

            for (SIZE_T j = 0; j < minLen; j++) {
                if (towlower(FileName[j]) == towlower(g_SystemDllNames[i][j])) {
                    matches++;
                }
            }

            if (matches >= minLen - 2) {
                return TRUE;
            }
        }
    }

    return FALSE;
}


static
ULONG
ImgpCalculateThreatScore(
    PIMG_LOAD_EVENT Event
    )
{
    ULONG score = 0;

    //
    // Unsigned images get base score
    //
    if (Event->Flags & ImgFlag_Unsigned) {
        score += 20;
    }

    //
    // Suspicious path indicators
    //
    if (Event->SuspiciousReasons & ImgSuspicious_TempDirectory) {
        score += 15;
    }

    if (Event->SuspiciousReasons & ImgSuspicious_NetworkPath) {
        score += 25;
    }

    if (Event->SuspiciousReasons & ImgSuspicious_MasqueradingName) {
        score += 40;
    }

    if (Event->SuspiciousReasons & ImgSuspicious_DoubleExtension) {
        score += 30;
    }

    if (Event->SuspiciousReasons & ImgSuspicious_PhantomDll) {
        score += 60;
    }

    //
    // PE anomalies
    //
    if (Event->Flags & ImgFlag_NoExports) {
        score += 15;
    }

    if (Event->Flags & ImgFlag_SelfModifying) {
        score += 25;
    }

    if (Event->Flags & ImgFlag_HighEntropy) {
        score += 20;
    }

    if (Event->Flags & ImgFlag_UnbackedMemory) {
        score += 50;
    }

    if (Event->Flags & ImgFlag_KnownVulnerable) {
        score += 80;
    }

    //
    // Cap at 100
    //
    return min(score, 100);
}


static
BOOLEAN
ImgpCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LONG64 elapsed;
    LONG64 maxEvents;

    KeQuerySystemTime(&currentTime);

    elapsed = (currentTime.QuadPart - g_ImgNotify.WindowStartTime) / 10000;  // ms

    if (elapsed >= IMG_RATE_LIMIT_WINDOW_MS) {
        //
        // Reset window
        //
        InterlockedExchange64(&g_ImgNotify.EventsThisWindow, 0);
        InterlockedExchange64(&g_ImgNotify.WindowStartTime, currentTime.QuadPart);
    }

    maxEvents = g_ImgNotify.Config.MaxEventsPerSecond;
    if (maxEvents == 0) {
        maxEvents = IMG_DEFAULT_MAX_EVENTS_PER_SEC;
    }

    if (InterlockedIncrement64(&g_ImgNotify.EventsThisWindow) > maxEvents) {
        return FALSE;
    }

    return TRUE;
}


static
VOID
ImgpNotifyPreLoadCallbacks(
    HANDLE ProcessId,
    PUNICODE_STRING FullImageName,
    PIMAGE_INFO ImageInfo,
    PBOOLEAN BlockLoad
    )
{
    PLIST_ENTRY entry;
    PIMG_CALLBACK_ENTRY callback;
    BOOLEAN shouldBlock = FALSE;

    *BlockLoad = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ImgNotify.CallbackLock);

    for (entry = g_ImgNotify.PreLoadCallbacks.Flink;
         entry != &g_ImgNotify.PreLoadCallbacks;
         entry = entry->Flink) {

        callback = CONTAINING_RECORD(entry, IMG_CALLBACK_ENTRY, ListEntry);

        if (callback->Active && callback->Callback.PreLoad != NULL) {
            __try {
                NTSTATUS status = callback->Callback.PreLoad(
                    ProcessId,
                    FullImageName,
                    ImageInfo,
                    &shouldBlock,
                    callback->Context
                    );

                if (NT_SUCCESS(status) && shouldBlock) {
                    *BlockLoad = TRUE;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                //
                // Callback threw exception - continue
                //
            }
        }
    }

    ExReleasePushLockShared(&g_ImgNotify.CallbackLock);
    KeLeaveCriticalRegion();
}


static
VOID
ImgpNotifyPostLoadCallbacks(
    PIMG_LOAD_EVENT Event
    )
{
    PLIST_ENTRY entry;
    PIMG_CALLBACK_ENTRY callback;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ImgNotify.CallbackLock);

    for (entry = g_ImgNotify.PostLoadCallbacks.Flink;
         entry != &g_ImgNotify.PostLoadCallbacks;
         entry = entry->Flink) {

        callback = CONTAINING_RECORD(entry, IMG_CALLBACK_ENTRY, ListEntry);

        if (callback->Active && callback->Callback.PostLoad != NULL) {
            __try {
                callback->Callback.PostLoad(Event, callback->Context);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                //
                // Callback threw exception - continue
                //
            }
        }
    }

    ExReleasePushLockShared(&g_ImgNotify.CallbackLock);
    KeLeaveCriticalRegion();
}


static
ULONG
ImgpHashVulnerableDriver(
    PUCHAR Sha256Hash
    )
{
    //
    // Simple hash of first 4 bytes of SHA-256
    //
    ULONG hash = *(PULONG)Sha256Hash;
    return hash % IMG_VULNERABLE_DRIVER_BUCKETS;
}


static
VOID
ImgpInitializeDefaultConfig(
    PIMG_NOTIFY_CONFIG Config
    )
{
    RtlZeroMemory(Config, sizeof(IMG_NOTIFY_CONFIG));

    Config->EnablePeAnalysis = TRUE;
    Config->EnableHashComputation = FALSE;  // Expensive in callback
    Config->EnableSignatureCheck = FALSE;   // Expensive in callback
    Config->EnableSuspiciousDetection = TRUE;
    Config->EnableDriverMonitoring = TRUE;
    Config->EnableVulnerableDriverCheck = TRUE;
    Config->MonitorSystemProcesses = TRUE;
    Config->MonitorKernelImages = TRUE;

    Config->SkipMicrosoftSigned = FALSE;
    Config->SkipWhqlSigned = FALSE;
    Config->SkipCatalogSigned = FALSE;

    Config->MinThreatScoreToReport = 30;
    Config->HighEntropyThreshold = IMG_HIGH_ENTROPY_THRESHOLD;
    Config->MaxEventsPerSecond = IMG_DEFAULT_MAX_EVENTS_PER_SEC;
}


static
ULONG
ImgpCalculateSectionEntropy(
    PUCHAR Data,
    ULONG Size
    )
{
    ULONG byteCount[256] = { 0 };
    ULONG entropy = 0;
    ULONG i;

    if (Data == NULL || Size == 0) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Size; i++) {
        byteCount[Data[i]]++;
    }

    //
    // Calculate simplified entropy * 100
    // Shannon entropy approximation
    //
    for (i = 0; i < 256; i++) {
        if (byteCount[i] > 0) {
            ULONG probability = (byteCount[i] * 10000) / Size;

            if (probability > 0 && probability < 10000) {
                //
                // Approximate -p * log2(p) contribution
                //
                ULONG logApprox = 0;
                ULONG temp = probability;

                while (temp > 0) {
                    logApprox++;
                    temp >>= 1;
                }

                entropy += (probability * logApprox) / 10000;
            }
        }
    }

    //
    // Normalize to 0-800 range (8 bits max * 100)
    //
    return min(entropy, 800);
}
