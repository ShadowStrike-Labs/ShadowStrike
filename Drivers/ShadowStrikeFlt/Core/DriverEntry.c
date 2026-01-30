/**
 * ============================================================================
 * ShadowStrike NGAV - DRIVER ENTRY POINT
 * ============================================================================
 *
 * @file DriverEntry.c
 * @brief Main driver entry point and initialization.
 *
 * This file contains DriverEntry, the main entry point called when the driver
 * is loaded. It initializes all subsystems in the correct order and handles
 * cleanup on failure.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "DriverEntry.h"
#include "FilterRegistration.h"
#include "../Communication/CommPort.h"
#include "../Cache/ScanCache.h"
#include "../Exclusions/ExclusionManager.h"
#include "../SelfProtection/SelfProtect.h"
#include "../Callbacks/Registry/RegistryCallback.h"
#include "../Utilities/HashUtils.h"
#include "../Shared/SharedDefs.h"
#include "../Shared/PortName.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ShadowStrikeUnload)
#pragma alloc_text(PAGE, ShadowStrikeInitializeLookasideLists)
#pragma alloc_text(PAGE, ShadowStrikeCleanupLookasideLists)
#pragma alloc_text(PAGE, ShadowStrikeRegisterProcessCallbacks)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterProcessCallbacks)
#pragma alloc_text(PAGE, ShadowStrikeRegisterRegistryCallback)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterRegistryCallback)
#pragma alloc_text(PAGE, ShadowStrikeRegisterObjectCallbacks)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterObjectCallbacks)
#endif

// ============================================================================
// GLOBAL DRIVER DATA
// ============================================================================

/**
 * @brief Global driver data instance.
 *
 * Single instance of driver state, initialized in DriverEntry.
 */
SHADOWSTRIKE_DRIVER_DATA g_DriverData = {0};

// ============================================================================
// FORWARD DECLARATIONS FOR CALLBACKS
// ============================================================================

VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
ShadowStrikeThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

VOID
ShadowStrikeImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    );

// ============================================================================
// DRIVER ENTRY
// ============================================================================

/**
 * @brief Main driver entry point.
 *
 * Initialization order is critical:
 * 1. Initialize global state
 * 2. Create lookaside lists
 * 3. Register minifilter
 * 4. Create communication port
 * 5. Register process/thread callbacks
 * 6. Register registry callback
 * 7. Register object callbacks (self-protection)
 * 8. Start filtering
 *
 * On any failure, cleanup is performed in reverse order.
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN filterRegistered = FALSE;
    BOOLEAN portCreated = FALSE;
    BOOLEAN lookasideInitialized = FALSE;
    BOOLEAN cacheInitialized = FALSE;
    BOOLEAN exclusionsInitialized = FALSE;
    BOOLEAN hashUtilsInitialized = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] DriverEntry: Starting initialization (v%u.%u.%u)\n",
               SHADOWSTRIKE_VERSION_MAJOR,
               SHADOWSTRIKE_VERSION_MINOR,
               SHADOWSTRIKE_VERSION_BUILD);

    //
    // Step 1: Initialize global state
    //
    RtlZeroMemory(&g_DriverData, sizeof(SHADOWSTRIKE_DRIVER_DATA));
    g_DriverData.DriverObject = DriverObject;

    KeInitializeEvent(&g_DriverData.UnloadEvent, NotificationEvent, FALSE);
    ExInitializePushLock(&g_DriverData.ClientPortLock);
    ExInitializePushLock(&g_DriverData.ConfigLock);
    ExInitializePushLock(&g_DriverData.ProtectedProcessLock);

    InitializeListHead(&g_DriverData.ProtectedProcessList);

    // Initialize default configuration
    ShadowStrikeInitDefaultConfig(&g_DriverData.Config);

    // Record start time
    KeQuerySystemTime(&g_DriverData.Stats.StartTime);

    //
    // Step 2: Initialize lookaside lists for memory allocation
    //
    status = ShadowStrikeInitializeLookasideLists();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to initialize lookaside lists: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    lookasideInitialized = TRUE;
    g_DriverData.LookasideInitialized = TRUE;

    //
    // Step 3: Register the minifilter
    //
    status = FltRegisterFilter(
        DriverObject,
        ShadowStrikeGetFilterRegistration(),
        &g_DriverData.FilterHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltRegisterFilter failed: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    filterRegistered = TRUE;
    ShadowStrikeLogInitStatus("FltRegisterFilter", status);

    //
    // Step 4: Create communication port
    //
    status = ShadowStrikeCreateCommunicationPort(g_DriverData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to create communication port: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    portCreated = TRUE;
    ShadowStrikeLogInitStatus("Communication Port", status);

    //
    // Step 5: Initialize scan cache
    //
    status = ShadowStrikeCacheInitialize(g_DriverData.Config.CacheTTLSeconds);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to initialize scan cache: 0x%08X\n",
                   status);
        // Non-fatal - continue without caching
        status = STATUS_SUCCESS;
    } else {
        cacheInitialized = TRUE;
        ShadowStrikeLogInitStatus("Scan Cache", STATUS_SUCCESS);
    }

    //
    // Step 6: Initialize exclusion manager
    //
    status = ShadowStrikeExclusionInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to initialize exclusion manager: 0x%08X\n",
                   status);
        // Non-fatal - continue without exclusions
        status = STATUS_SUCCESS;
    } else {
        exclusionsInitialized = TRUE;
        ShadowStrikeLogInitStatus("Exclusion Manager", STATUS_SUCCESS);
    }

    //
    // Step 7: Initialize hash utilities (CNG provider)
    //
    status = ShadowStrikeInitializeHashUtils();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to initialize hash utilities: 0x%08X\n",
                   status);
        // Non-fatal - continue without kernel-side hashing
        status = STATUS_SUCCESS;
    } else {
        hashUtilsInitialized = TRUE;
        ShadowStrikeLogInitStatus("Hash Utilities", STATUS_SUCCESS);
    }

    //
    // Step 8: Register process/thread notification callbacks
    //
    status = ShadowStrikeRegisterProcessCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to register process callbacks: 0x%08X\n",
                   status);
        // Non-fatal - continue without process monitoring
        status = STATUS_SUCCESS;
    }

    //
    // Step 9: Register registry callback
    //
    status = ShadowStrikeRegisterRegistryCallback();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to register registry callback: 0x%08X\n",
                   status);
        // Non-fatal - continue without registry monitoring
        status = STATUS_SUCCESS;
    }

    //
    // Step 9: Register object callbacks for self-protection
    //
    status = ShadowStrikeRegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to register object callbacks: 0x%08X\n",
                   status);
        // Non-fatal - continue without handle protection
        status = STATUS_SUCCESS;
    }

    //
    // Step 10: Start filtering
    //
    status = FltStartFiltering(g_DriverData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltStartFiltering failed: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    g_DriverData.FilteringStarted = TRUE;
    ShadowStrikeLogInitStatus("FltStartFiltering", status);

    //
    // Mark driver as initialized
    //
    g_DriverData.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Driver initialized successfully\n");

    return STATUS_SUCCESS;

Cleanup:
    //
    // Cleanup in reverse order
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[ShadowStrike] DriverEntry failed, cleaning up...\n");

    ShadowStrikeUnregisterObjectCallbacks();
    ShadowStrikeUnregisterRegistryCallback();
    ShadowStrikeUnregisterProcessCallbacks();

    if (hashUtilsInitialized) {
        ShadowStrikeCleanupHashUtils();
    }

    if (portCreated) {
        ShadowStrikeCloseCommunicationPort();
    }

    if (filterRegistered) {
        FltUnregisterFilter(g_DriverData.FilterHandle);
        g_DriverData.FilterHandle = NULL;
    }

    if (lookasideInitialized) {
        ShadowStrikeCleanupLookasideLists();
    }

    ShadowStrikeCleanupProtectedProcessList();

    return status;
}

// ============================================================================
// DRIVER UNLOAD
// ============================================================================

/**
 * @brief Driver unload callback.
 *
 * Called by Filter Manager when driver is being unloaded.
 * Must wait for all outstanding operations to complete before
 * freeing resources.
 */
NTSTATUS
ShadowStrikeUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Unload: Starting driver unload\n");

    //
    // Signal shutdown - stop accepting new work
    //
    g_DriverData.ShuttingDown = TRUE;

    //
    // Wait for outstanding operations to complete (max 30 seconds)
    //
    if (g_DriverData.OutstandingOperations > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Waiting for %ld outstanding operations\n",
                   g_DriverData.OutstandingOperations);

        ShadowStrikeWaitForOutstandingOperations(30000);
    }

    //
    // Unregister callbacks in reverse order of registration
    //
    ShadowStrikeUnregisterObjectCallbacks();
    ShadowStrikeUnregisterRegistryCallback();
    ShadowStrikeUnregisterProcessCallbacks();

    //
    // Shutdown exclusion manager
    //
    ShadowStrikeExclusionShutdown();

    //
    // Cleanup hash utilities
    //
    ShadowStrikeCleanupHashUtils();

    //
    // Close communication port (disconnects all clients)
    //
    ShadowStrikeCloseCommunicationPort();

    //
    // Unregister filter
    //
    if (g_DriverData.FilterHandle != NULL) {
        FltUnregisterFilter(g_DriverData.FilterHandle);
        g_DriverData.FilterHandle = NULL;
    }

    //
    // Cleanup lookaside lists
    //
    if (g_DriverData.LookasideInitialized) {
        ShadowStrikeCleanupLookasideLists();
        g_DriverData.LookasideInitialized = FALSE;
    }

    //
    // Cleanup protected process list
    //
    ShadowStrikeCleanupProtectedProcessList();

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Final stats: Scanned=%lld, Blocked=%lld, CacheHits=%lld\n",
               g_DriverData.Stats.TotalFilesScanned,
               g_DriverData.Stats.FilesBlocked,
               g_DriverData.Stats.CacheHits);

    g_DriverData.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Driver unloaded successfully\n");

    return STATUS_SUCCESS;
}

// ============================================================================
// LOOKASIDE LIST MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeInitializeLookasideLists(
    VOID
    )
{
    PAGED_CODE();

    //
    // Message lookaside - for kernel<->user messages
    //
    ExInitializeNPagedLookasideList(
        &g_DriverData.MessageLookaside,
        NULL,                           // Allocate function (use default)
        NULL,                           // Free function (use default)
        POOL_NX_ALLOCATION,             // Non-executable pool
        SHADOWSTRIKE_MAX_MESSAGE_SIZE,  // Entry size
        SHADOWSTRIKE_POOL_TAG,          // Pool tag
        0                               // Depth (0 = system default)
    );

    //
    // Stream context lookaside - for per-file tracking
    //
    ExInitializeNPagedLookasideList(
        &g_DriverData.StreamContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOWSTRIKE_STREAM_CONTEXT),
        SHADOWSTRIKE_POOL_TAG,
        0
    );

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeCleanupLookasideLists(
    VOID
    )
{
    PAGED_CODE();

    ExDeleteNPagedLookasideList(&g_DriverData.MessageLookaside);
    ExDeleteNPagedLookasideList(&g_DriverData.StreamContextLookaside);
}

// ============================================================================
// PROCESS CALLBACK REGISTRATION
// ============================================================================

NTSTATUS
ShadowStrikeRegisterProcessCallbacks(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    //
    // Register process creation/termination callback
    //
    status = PsSetCreateProcessNotifyRoutineEx(
        ShadowStrikeProcessNotifyCallback,
        FALSE   // Register (not remove)
    );

    if (NT_SUCCESS(status)) {
        g_DriverData.ProcessNotifyRegistered = TRUE;
        ShadowStrikeLogInitStatus("Process Notify", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n",
                   status);
        return status;
    }

    //
    // Register thread creation callback
    //
    status = PsSetCreateThreadNotifyRoutine(ShadowStrikeThreadNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_DriverData.ThreadNotifyRegistered = TRUE;
        ShadowStrikeLogInitStatus("Thread Notify", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] PsSetCreateThreadNotifyRoutine failed: 0x%08X\n",
                   status);
        // Non-fatal
    }

    //
    // Register image load callback
    //
    status = PsSetLoadImageNotifyRoutine(ShadowStrikeImageNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_DriverData.ImageNotifyRegistered = TRUE;
        ShadowStrikeLogInitStatus("Image Notify", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] PsSetLoadImageNotifyRoutine failed: 0x%08X\n",
                   status);
        // Non-fatal
    }

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeUnregisterProcessCallbacks(
    VOID
    )
{
    PAGED_CODE();

    if (g_DriverData.ImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(ShadowStrikeImageNotifyCallback);
        g_DriverData.ImageNotifyRegistered = FALSE;
    }

    if (g_DriverData.ThreadNotifyRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ShadowStrikeThreadNotifyCallback);
        g_DriverData.ThreadNotifyRegistered = FALSE;
    }

    if (g_DriverData.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(
            ShadowStrikeProcessNotifyCallback,
            TRUE    // Remove
        );
        g_DriverData.ProcessNotifyRegistered = FALSE;
    }
}

// ============================================================================
// REGISTRY CALLBACK REGISTRATION
// ============================================================================

NTSTATUS
ShadowStrikeRegisterRegistryCallback(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    PAGED_CODE();

    RtlInitUnicodeString(&altitude, SHADOWSTRIKE_ALTITUDE_W);

    status = CmRegisterCallbackEx(
        ShadowStrikeRegistryCallbackRoutine,
        &altitude,
        g_DriverData.DriverObject,
        NULL,                                   // Context
        &g_DriverData.RegistryCallbackCookie,
        NULL                                    // Reserved
    );

    if (NT_SUCCESS(status)) {
        ShadowStrikeLogInitStatus("Registry Callback", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] CmRegisterCallbackEx failed: 0x%08X\n",
                   status);
    }

    return status;
}

VOID
ShadowStrikeUnregisterRegistryCallback(
    VOID
    )
{
    PAGED_CODE();

    if (g_DriverData.RegistryCallbackCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_DriverData.RegistryCallbackCookie);
        g_DriverData.RegistryCallbackCookie.QuadPart = 0;
    }
}

// ============================================================================
// OBJECT CALLBACK REGISTRATION (SELF-PROTECTION)
// ============================================================================

// Object callback operation registration
OB_OPERATION_REGISTRATION g_ObjectOperations[] = {
    {
        PsProcessType,                              // ObjectType
        OB_OPERATION_HANDLE_CREATE |                // Operations
        OB_OPERATION_HANDLE_DUPLICATE,
        NULL,                                       // PreOperation - set in registration
        NULL                                        // PostOperation
    },
    {
        PsThreadType,                               // ObjectType
        OB_OPERATION_HANDLE_CREATE |                // Operations
        OB_OPERATION_HANDLE_DUPLICATE,
        NULL,                                       // PreOperation - set in registration
        NULL                                        // PostOperation
    }
};

// Forward declare the pre-operation callback from SelfProtect.c
OB_PREOP_CALLBACK_STATUS
ShadowStrikeObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

NTSTATUS
ShadowStrikeRegisterObjectCallbacks(
    VOID
    )
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION callbackReg;
    UNICODE_STRING altitude;

    PAGED_CODE();

    //
    // Setup operation registrations with callbacks
    //
    g_ObjectOperations[0].PreOperation = ShadowStrikeObjectPreCallback;
    g_ObjectOperations[1].PreOperation = ShadowStrikeObjectPreCallback;

    RtlInitUnicodeString(&altitude, SHADOWSTRIKE_ALTITUDE_W);

    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = ARRAYSIZE(g_ObjectOperations);
    callbackReg.Altitude = altitude;
    callbackReg.RegistrationContext = NULL;
    callbackReg.OperationRegistration = g_ObjectOperations;

    status = ObRegisterCallbacks(&callbackReg, &g_DriverData.ObjectCallbackHandle);

    if (NT_SUCCESS(status)) {
        ShadowStrikeLogInitStatus("Object Callbacks", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ObRegisterCallbacks failed: 0x%08X\n",
                   status);
        g_DriverData.ObjectCallbackHandle = NULL;
    }

    return status;
}

VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    )
{
    PAGED_CODE();

    if (g_DriverData.ObjectCallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_DriverData.ObjectCallbackHandle);
        g_DriverData.ObjectCallbackHandle = NULL;
    }
}

// ============================================================================
// PROTECTED PROCESS LIST MANAGEMENT
// ============================================================================

VOID
ShadowStrikeInitializeProtectedProcessList(
    VOID
    )
{
    // Already initialized in DriverEntry
}

VOID
ShadowStrikeCleanupProtectedProcessList(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;

    //
    // Free all entries in the protected process list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    for (entry = g_DriverData.ProtectedProcessList.Flink;
         entry != &g_DriverData.ProtectedProcessList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        RemoveEntryList(entry);
        ExFreePoolWithTag(entry, SHADOWSTRIKE_POOL_TAG);
    }

    g_DriverData.ProtectedProcessCount = 0;

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

NTSTATUS
ShadowStrikeWaitForOutstandingOperations(
    _In_ ULONG TimeoutMs
    )
{
    LARGE_INTEGER interval;
    ULONG waited = 0;
    ULONG sleepMs = 100;

    interval.QuadPart = -(LONGLONG)sleepMs * 10000; // 100ms in 100ns units

    while (g_DriverData.OutstandingOperations > 0 && waited < TimeoutMs) {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waited += sleepMs;
    }

    if (g_DriverData.OutstandingOperations > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Timeout waiting for operations: %ld remaining\n",
                   g_DriverData.OutstandingOperations);
        return STATUS_TIMEOUT;
    }

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeLogInitStatus(
    _In_ PCSTR Component,
    _In_ NTSTATUS Status
    )
{
    if (NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] %s: OK\n", Component);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] %s: FAILED (0x%08X)\n", Component, Status);
    }
}

// ============================================================================
// STUB CALLBACK IMPLEMENTATIONS
// ============================================================================
// These will be fully implemented in their respective files

VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);

    if (!SHADOWSTRIKE_IS_READY()) {
        return;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    if (CreateInfo != NULL) {
        // Process creation
        InterlockedIncrement64(&g_DriverData.Stats.TotalProcessCreations);

        // TODO: Send to user-mode for analysis
        // For now, just log
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Process created: PID=%p\n", ProcessId);
    } else {
        // Process termination
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Process terminated: PID=%p\n", ProcessId);
    }

    SHADOWSTRIKE_LEAVE_OPERATION();
}

VOID
ShadowStrikeThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);

    // Thread notifications are informational only
    // Full implementation in ThreadNotify.c
}

VOID
ShadowStrikeImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    // Image load notifications
    // Full implementation in ImageNotify.c
}

NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    if (!SHADOWSTRIKE_IS_READY()) {
        return STATUS_SUCCESS;
    }

    // Registry callback
    // Full implementation in RegistryCallback.c
    InterlockedIncrement64(&g_DriverData.Stats.TotalRegistryOperations);

    return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS
ShadowStrikeObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!SHADOWSTRIKE_IS_READY()) {
        return OB_PREOP_SUCCESS;
    }

    if (!g_DriverData.Config.SelfProtectionEnabled) {
        return OB_PREOP_SUCCESS;
    }

    // Self-protection logic
    // Full implementation in SelfProtection/HandleProtection.c

    // For now, allow all operations
    // The full implementation will:
    // 1. Check if target is a protected process
    // 2. Strip dangerous access rights (PROCESS_TERMINATE, PROCESS_VM_WRITE, etc.)

    UNREFERENCED_PARAMETER(OperationInformation);

    return OB_PREOP_SUCCESS;
}
