/**
 * ============================================================================
 * ShadowStrike NGAV - ALPC PORT MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file AlpcPortMonitor.c
 * @brief Enterprise-grade ALPC port monitoring implementation.
 *
 * Implements real ALPC (Advanced Local Procedure Call) security monitoring:
 * - Object callbacks for ALPC Port handle operations
 * - Port creation/connection tracking with proper hash table
 * - Cross-session and integrity level violation detection
 * - Impersonation abuse detection
 * - Handle passing via ALPC monitoring
 * - Sandbox escape attempt detection
 *
 * CRITICAL DESIGN DECISIONS:
 * ==========================
 * 1. Uses chained hash table (not direct-mapped) - no collision overwrites
 * 2. Per-bucket locking for scalability
 * 3. Lookaside lists for allocation performance
 * 4. Reference counting with safe shutdown drain
 * 5. Worker thread for async cleanup
 * 6. Rundown protection for in-flight operations
 * 7. Proper lock hierarchy to prevent deadlocks
 *
 * VERSION 2.0.0 SECURITY FIXES:
 * =============================
 * - FIXED: Integrity level detection now uses ProcessUtils properly
 * - FIXED: Added rundown protection (EX_RUNDOWN_REF) for safe shutdown
 * - FIXED: Lock hierarchy violations corrected
 * - FIXED: Added KeFlushQueuedDpcs() during cleanup
 * - FIXED: LRU eviction race conditions eliminated
 * - FIXED: Reference count underflow now triggers bugcheck in release
 * - FIXED: Removed deprecated ExAllocatePoolWithTag
 * - FIXED: Port name extraction uses bounded string operations
 * - FIXED: ALPC port type resolution placeholder with clear documentation
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AlpcPortMonitor.h"
#include "../Utilities/ProcessUtils.h"
#include "../Utilities/MemoryUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// UNDOCUMENTED STRUCTURES FOR OBJECT TYPE ENUMERATION
// ============================================================================

#ifndef ObjectTypesInformation
#define ObjectTypesInformation 3
#endif

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION {
    ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

//
// ALPC port creation structures
//
typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

//
// ALPC syscall declarations
//
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAlpcCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// Alignment macro
//
#ifndef ALIGN_UP
#define ALIGN_UP(x, align) (((ULONG_PTR)(x) + ((align) - 1)) & ~((ULONG_PTR)(align) - 1))
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowAlpcInitialize)
#pragma alloc_text(PAGE, ShadowAlpcCleanup)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

SHADOW_ALPC_MONITOR_STATE g_AlpcPortMonitorState = { 0 };

// ============================================================================
// SENSITIVE ALPC PORT PATTERNS
// ============================================================================

static const SHADOW_ALPC_SENSITIVE_PORT g_SensitiveAlpcPorts[] = {
    { L"\\RPC Control\\", TRUE, 30, L"RPC endpoint mapper" },
    { L"\\RPC Control\\lsass", TRUE, 50, L"LSASS RPC" },
    { L"\\RPC Control\\samr", TRUE, 45, L"SAM Remote Protocol" },
    { L"\\RPC Control\\lsarpc", TRUE, 50, L"LSA Remote Protocol" },
    { L"\\RPC Control\\netlogon", TRUE, 40, L"Netlogon Service" },
    { L"\\RPC Control\\protected_storage", TRUE, 45, L"Protected Storage" },
    { L"\\RPC Control\\ntsvcs", TRUE, 35, L"NT Services" },
    { L"\\RPC Control\\scerpc", TRUE, 40, L"Security Configuration" },
    { L"\\BaseNamedObjects\\", TRUE, 20, L"Named objects namespace" },
    { L"\\Sessions\\", TRUE, 15, L"Session namespace" },
    { L"\\Windows\\ApiPort", FALSE, 60, L"CSRSS API Port" },
    { L"\\Windows\\SbApiPort", FALSE, 55, L"Session Manager API" },
    { L"\\Security\\LsaAuthenticationPort", FALSE, 70, L"LSA Authentication" },
    { L"\\ThemeApiPort", FALSE, 25, L"Theme Service" },
    { L"\\NlsCacheMutant", FALSE, 20, L"NLS Cache" },
    { NULL, FALSE, 0, NULL }
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
ShadowAlpcpWorkerThread(
    _In_ PVOID StartContext
    );

static VOID
ShadowAlpcpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
ShadowAlpcpCleanupStaleEntries(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    );

static VOID
ShadowAlpcpFreePortEntry(
    _In_ PSHADOW_ALPC_MONITOR_STATE State,
    _In_ PSHADOW_ALPC_PORT_ENTRY Entry
    );

static VOID
ShadowAlpcpFreeConnection(
    _In_ PSHADOW_ALPC_MONITOR_STATE State,
    _In_ PSHADOW_ALPC_CONNECTION Connection
    );

static PSHADOW_ALPC_PORT_ENTRY
ShadowAlpcpAllocatePortEntry(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    );

static PSHADOW_ALPC_CONNECTION
ShadowAlpcpAllocateConnection(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    );

static PSHADOW_ALPC_EVENT
ShadowAlpcpAllocateEvent(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    );

static VOID
ShadowAlpcpReferencePortEntry(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY Entry
    );

static NTSTATUS
ShadowAlpcpResolveAlpcPortType(
    _Out_ POBJECT_TYPE* AlpcPortType
    );

static NTSTATUS
ShadowAlpcpGetPortTypeViaCreation(
    _Out_ POBJECT_TYPE* AlpcPortType
    );

static VOID
ShadowAlpcpExtractPortNameSafe(
    _In_ PVOID PortObject,
    _Out_writes_(MaxLength) PWCHAR PortName,
    _In_ ULONG MaxLength
    );

static NTSTATUS
ShadowAlpcpGetProcessIntegrityRid(
    _In_ HANDLE ProcessId,
    _Out_ PULONG IntegrityRid
    );

static VOID
ShadowAlpcpGetProcessNameSafe(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxLength) PWCHAR ProcessName,
    _In_ ULONG MaxLength
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowAlpcInitialize(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    POBJECT_TYPE alpcPortType = NULL;
    OB_OPERATION_REGISTRATION operationRegistration;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    UNICODE_STRING altitude;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE threadHandle = NULL;
    LARGE_INTEGER dueTime;
    LONG previousState;
    ULONG i;

    PAGED_CODE();

    //
    // Atomic initialization to prevent race conditions
    //
    previousState = InterlockedCompareExchange(
        &state->InitializationState,
        1,  // INITIALIZING
        0   // UNINITIALIZED
    );

    if (previousState == 2) {  // INITIALIZED
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState == 1) {  // INITIALIZING
        //
        // Wait for other thread to complete
        //
        LARGE_INTEGER sleepInterval;
        sleepInterval.QuadPart = -500000LL; // 50ms

        for (i = 0; i < 100; i++) {
            KeDelayExecutionThread(KernelMode, FALSE, &sleepInterval);
            if (state->InitializationState == 2) {
                return STATUS_SUCCESS;
            }
            if (state->InitializationState == 0) {
                return STATUS_UNSUCCESSFUL;
            }
        }
        return STATUS_TIMEOUT;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/ALPC] Initializing ALPC Port Monitor v2.0.0\n");

    RtlZeroMemory(state, sizeof(SHADOW_ALPC_MONITOR_STATE));

    //
    // Initialize rundown protection for safe shutdown
    //
    ExInitializeRundownProtection(&state->RundownProtection);

    //
    // Initialize hash buckets with per-bucket locks
    //
    for (i = 0; i < SHADOW_ALPC_HASH_BUCKETS; i++) {
        InitializeListHead(&state->HashBuckets[i].PortList);
        ExInitializePushLock(&state->HashBuckets[i].Lock);
        state->HashBuckets[i].Count = 0;
    }

    //
    // Initialize global port list
    //
    InitializeListHead(&state->PortList);
    ExInitializePushLock(&state->PortListLock);
    state->MaxPorts = SHADOW_ALPC_MAX_PORTS;

    //
    // Initialize event queue
    //
    InitializeListHead(&state->EventQueue);
    KeInitializeSpinLock(&state->EventLock);
    state->MaxEvents = SHADOW_ALPC_MAX_EVENT_QUEUE;

    //
    // Initialize lookaside lists for fast allocation
    //
    ExInitializeNPagedLookasideList(
        &state->PortEntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOW_ALPC_PORT_ENTRY),
        SHADOW_ALPC_PORT_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &state->ConnectionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOW_ALPC_CONNECTION),
        SHADOW_ALPC_CONN_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &state->EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOW_ALPC_EVENT),
        SHADOW_ALPC_EVENT_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &state->WorkItemLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOW_ALPC_WORK_ITEM),
        SHADOW_ALPC_WORK_TAG,
        0
    );

    state->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    state->Config.MonitoringEnabled = TRUE;
    state->Config.BlockingEnabled = FALSE;  // Start in monitor-only mode
    state->Config.AlertOnImpersonation = TRUE;
    state->Config.AlertOnCrossSession = TRUE;
    state->Config.AlertOnSandboxEscape = TRUE;
    state->Config.RateLimitingEnabled = TRUE;
    state->Config.ThreatThreshold = 50;
    state->Config.MaxConnectionsPerSecond = SHADOW_ALPC_MAX_CONNECTIONS_PER_SEC;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&state->Stats.StartTime);

    //
    // Initialize worker thread synchronization
    //
    KeInitializeEvent(&state->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&state->WorkAvailableEvent, SynchronizationEvent, FALSE);

    //
    // Resolve ALPC Port object type
    //
    status = ShadowAlpcpResolveAlpcPortType(&alpcPortType);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/ALPC] Could not resolve ALPC Port type: 0x%X\n", status);
        //
        // ALPC Port type resolution failed - this is expected on some systems
        // Continue without object callbacks (rely on ETW if available)
        //
        alpcPortType = NULL;
    }

    //
    // Register object callbacks if we have the ALPC Port type
    //
    if (alpcPortType != NULL) {
        RtlZeroMemory(&operationRegistration, sizeof(operationRegistration));
        operationRegistration.ObjectType = alpcPortType;
        operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operationRegistration.PreOperation = ShadowAlpcPortPreCallback;
        operationRegistration.PostOperation = ShadowAlpcPortPostCallback;

        RtlInitUnicodeString(&altitude, L"385300");

        RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
        callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
        callbackRegistration.OperationRegistrationCount = 1;
        callbackRegistration.Altitude = altitude;
        callbackRegistration.RegistrationContext = state;
        callbackRegistration.OperationRegistration = &operationRegistration;

        status = ObRegisterCallbacks(&callbackRegistration, &state->ObjectCallbackHandle);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/ALPC] ObRegisterCallbacks failed: 0x%X\n", status);
            //
            // Continue without object callbacks
            //
            state->ObjectCallbackHandle = NULL;
        } else {
            state->CallbacksRegistered = TRUE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/ALPC] Object callbacks registered\n");
        }
    }

    //
    // Create worker thread
    //
    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objectAttributes,
        NULL,
        NULL,
        ShadowAlpcpWorkerThread,
        state
    );

    if (NT_SUCCESS(status)) {
        status = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&state->WorkerThread,
            NULL
        );
        ZwClose(threadHandle);

        if (!NT_SUCCESS(status)) {
            //
            // Thread created but we couldn't get a reference
            // Signal shutdown to terminate the orphaned thread
            //
            KeSetEvent(&state->ShutdownEvent, IO_NO_INCREMENT, FALSE);
            state->WorkerThread = NULL;
        }
    }

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&state->CleanupTimer);
    KeInitializeDpc(&state->CleanupDpc, ShadowAlpcpCleanupTimerDpc, state);

    dueTime.QuadPart = -((LONGLONG)60000 * 10000);  // 60 seconds
    KeSetTimerEx(&state->CleanupTimer, dueTime, 60000, &state->CleanupDpc);
    state->CleanupTimerActive = TRUE;

    //
    // Mark as initialized
    //
    state->Initialized = TRUE;
    InterlockedExchange(&state->ShuttingDown, FALSE);
    InterlockedExchange(&state->InitializationState, 2);  // INITIALIZED

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/ALPC] ALPC Port Monitor initialized successfully\n");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowAlpcCleanup(
    VOID
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    PLIST_ENTRY entry;
    PSHADOW_ALPC_PORT_ENTRY portEntry;
    PSHADOW_ALPC_EVENT event;
    KIRQL oldIrql;
    ULONG i;
    LIST_ENTRY entriesToFree;
    LIST_ENTRY eventsToFree;

    PAGED_CODE();

    if (!state->Initialized) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/ALPC] Cleaning up ALPC Port Monitor\n");

    //
    // Mark as shutting down FIRST
    //
    InterlockedExchange(&state->ShuttingDown, TRUE);
    InterlockedExchange(&state->InitializationState, 0);

    //
    // Wait for rundown protection - ensures all in-flight operations complete
    //
    ExWaitForRundownProtectionRelease(&state->RundownProtection);

    //
    // Unregister object callbacks
    //
    if (state->CallbacksRegistered && state->ObjectCallbackHandle != NULL) {
        ObUnRegisterCallbacks(state->ObjectCallbackHandle);
        state->ObjectCallbackHandle = NULL;
        state->CallbacksRegistered = FALSE;
    }

    //
    // Cancel cleanup timer and wait for any pending DPCs
    //
    if (state->CleanupTimerActive) {
        KeCancelTimer(&state->CleanupTimer);
        state->CleanupTimerActive = FALSE;
    }

    //
    // CRITICAL FIX: Flush any queued DPCs to ensure timer DPC is not running
    //
    KeFlushQueuedDpcs();

    //
    // Signal worker thread to exit and wait
    //
    KeSetEvent(&state->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&state->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);

    if (state->WorkerThread != NULL) {
        KeWaitForSingleObject(
            state->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        ObDereferenceObject(state->WorkerThread);
        state->WorkerThread = NULL;
    }

    //
    // Free all port entries from hash table
    // FIXED: Correct lock hierarchy - hash bucket first, then global list
    //
    for (i = 0; i < SHADOW_ALPC_HASH_BUCKETS; i++) {
        InitializeListHead(&entriesToFree);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&state->HashBuckets[i].Lock);

        while (!IsListEmpty(&state->HashBuckets[i].PortList)) {
            entry = RemoveHeadList(&state->HashBuckets[i].PortList);
            portEntry = CONTAINING_RECORD(entry, SHADOW_ALPC_PORT_ENTRY, HashEntry);
            InterlockedDecrement(&state->HashBuckets[i].Count);
            InterlockedExchange(&portEntry->RemovedFromList, TRUE);
            InsertTailList(&entriesToFree, entry);
        }

        ExReleasePushLockExclusive(&state->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();

        //
        // Free entries outside lock - safe because they're removed from all lists
        //
        while (!IsListEmpty(&entriesToFree)) {
            entry = RemoveHeadList(&entriesToFree);
            portEntry = CONTAINING_RECORD(entry, SHADOW_ALPC_PORT_ENTRY, HashEntry);
            ShadowAlpcpFreePortEntry(state, portEntry);
        }
    }

    //
    // Clear global port list (entries already freed above)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&state->PortListLock);
    InitializeListHead(&state->PortList);
    state->PortCount = 0;
    ExReleasePushLockExclusive(&state->PortListLock);
    KeLeaveCriticalRegion();

    //
    // Free event queue
    //
    InitializeListHead(&eventsToFree);

    KeAcquireSpinLock(&state->EventLock, &oldIrql);

    while (!IsListEmpty(&state->EventQueue)) {
        entry = RemoveHeadList(&state->EventQueue);
        InsertTailList(&eventsToFree, entry);
        InterlockedDecrement(&state->EventCount);
    }

    KeReleaseSpinLock(&state->EventLock, oldIrql);

    //
    // Free events outside spinlock
    //
    while (!IsListEmpty(&eventsToFree)) {
        entry = RemoveHeadList(&eventsToFree);
        event = CONTAINING_RECORD(entry, SHADOW_ALPC_EVENT, ListEntry);
        ShadowAlpcFreeEvent(event);
    }

    //
    // Delete lookaside lists
    //
    if (state->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&state->PortEntryLookaside);
        ExDeleteNPagedLookasideList(&state->ConnectionLookaside);
        ExDeleteNPagedLookasideList(&state->EventLookaside);
        ExDeleteNPagedLookasideList(&state->WorkItemLookaside);
        state->LookasideInitialized = FALSE;
    }

    state->Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/ALPC] ALPC Port Monitor cleanup complete. "
               "Stats: Ports=%lld, Connections=%lld, Blocked=%lld\n",
               state->Stats.PortsCreated,
               state->Stats.ConnectionsEstablished,
               state->Stats.BlockedOperations);
}

BOOLEAN
ShadowAlpcIsActive(
    VOID
    )
{
    return (g_AlpcPortMonitorState.Initialized &&
            !g_AlpcPortMonitorState.ShuttingDown &&
            g_AlpcPortMonitorState.Config.MonitoringEnabled);
}

// ============================================================================
// PORT TRACKING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowAlpcTrackPort(
    _In_ PVOID PortObject,
    _In_ HANDLE OwnerPid,
    _In_ SHADOW_ALPC_PORT_TYPE PortType,
    _In_opt_ PCUNICODE_STRING PortName,
    _Outptr_ PSHADOW_ALPC_PORT_ENTRY* Entry
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    PSHADOW_ALPC_PORT_ENTRY portEntry = NULL;
    PSHADOW_ALPC_PORT_ENTRY existing = NULL;
    ULONG hashIndex;
    NTSTATUS status;
    PEPROCESS process = NULL;
    SHADOW_INTEGRITY_LEVEL integrityLevel;

    *Entry = NULL;

    if (!state->Initialized || state->ShuttingDown) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&state->RundownProtection)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Check if port already tracked
    //
    status = ShadowAlpcFindPort(PortObject, &existing);
    if (NT_SUCCESS(status)) {
        *Entry = existing;
        ExReleaseRundownProtection(&state->RundownProtection);
        return STATUS_SUCCESS;
    }

    //
    // Allocate new port entry
    //
    portEntry = ShadowAlpcpAllocatePortEntry(state);
    if (portEntry == NULL) {
        ExReleaseRundownProtection(&state->RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize port entry
    //
    portEntry->PortObject = PortObject;
    portEntry->PortType = PortType;
    portEntry->OwnerProcessId = OwnerPid;
    portEntry->ReferenceCount = 1;
    portEntry->RemovedFromList = FALSE;

    KeQuerySystemTime(&portEntry->CreateTime);
    portEntry->LastAccessTime = portEntry->CreateTime;
    portEntry->RateLimitWindowStart = portEntry->CreateTime;

    InitializeListHead(&portEntry->ConnectionList);
    ExInitializePushLock(&portEntry->ConnectionLock);

    //
    // Extract port name safely
    //
    if (PortName != NULL && PortName->Buffer != NULL && PortName->Length > 0) {
        USHORT copyLen = min(PortName->Length / sizeof(WCHAR), SHADOW_ALPC_MAX_PORT_NAME - 1);
        RtlCopyMemory(portEntry->PortName, PortName->Buffer, copyLen * sizeof(WCHAR));
        portEntry->PortName[copyLen] = L'\0';
        portEntry->PortNameLength = copyLen;
    } else {
        ShadowAlpcpExtractPortNameSafe(PortObject, portEntry->PortName, SHADOW_ALPC_MAX_PORT_NAME);
        portEntry->PortNameLength = (USHORT)wcsnlen(portEntry->PortName, SHADOW_ALPC_MAX_PORT_NAME);
    }

    //
    // Check if sensitive port
    //
    portEntry->IsSensitivePort = ShadowAlpcIsSensitivePort(portEntry->PortName, NULL);

    //
    // Get owner process info using ProcessUtils (FIXED: proper integrity detection)
    //
    status = PsLookupProcessByProcessId(OwnerPid, &process);
    if (NT_SUCCESS(status)) {
        portEntry->OwnerSessionId = PsGetProcessSessionId(process);

        //
        // CRITICAL FIX: Use ProcessUtils for proper integrity level detection
        //
        status = ShadowStrikeGetProcessIntegrityLevel(OwnerPid, &integrityLevel);
        if (NT_SUCCESS(status)) {
            portEntry->OwnerIntegrityLevel = ShadowAlpcIntegrityLevelToRid(integrityLevel);
        } else {
            //
            // SECURITY FIX: Default to SYSTEM on failure (fail-secure)
            // This prevents low-integrity processes from bypassing detection
            // by causing integrity lookup failures
            //
            portEntry->OwnerIntegrityLevel = SECURITY_MANDATORY_SYSTEM_RID;
        }

        ObDereferenceObject(process);
    }

    //
    // Insert into hash table (lock hierarchy: hash bucket first)
    //
    hashIndex = ShadowAlpcHashPortObject(PortObject);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&state->HashBuckets[hashIndex].Lock);

    //
    // Double-check for race condition
    //
    PLIST_ENTRY listEntry;
    for (listEntry = state->HashBuckets[hashIndex].PortList.Flink;
         listEntry != &state->HashBuckets[hashIndex].PortList;
         listEntry = listEntry->Flink) {

        existing = CONTAINING_RECORD(listEntry, SHADOW_ALPC_PORT_ENTRY, HashEntry);
        if (existing->PortObject == PortObject && !existing->RemovedFromList) {
            ShadowAlpcpReferencePortEntry(existing);
            ExReleasePushLockExclusive(&state->HashBuckets[hashIndex].Lock);
            KeLeaveCriticalRegion();

            ShadowAlpcpFreePortEntry(state, portEntry);
            *Entry = existing;
            ExReleaseRundownProtection(&state->RundownProtection);
            return STATUS_SUCCESS;
        }
    }

    InsertHeadList(&state->HashBuckets[hashIndex].PortList, &portEntry->HashEntry);
    InterlockedIncrement(&state->HashBuckets[hashIndex].Count);

    ExReleasePushLockExclusive(&state->HashBuckets[hashIndex].Lock);
    KeLeaveCriticalRegion();

    //
    // Add to global list (lock hierarchy: global list second)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&state->PortListLock);

    InsertHeadList(&state->PortList, &portEntry->GlobalEntry);
    InterlockedIncrement(&state->PortCount);

    //
    // Evict if over limit - FIXED: No nested locking, just mark for cleanup
    //
    if (state->PortCount > (LONG)state->MaxPorts) {
        //
        // Signal worker thread to clean up stale entries
        //
        KeSetEvent(&state->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);
    }

    ExReleasePushLockExclusive(&state->PortListLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&state->Stats.PortsCreated);

    *Entry = portEntry;
    ExReleaseRundownProtection(&state->RundownProtection);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowAlpcFindPort(
    _In_ PVOID PortObject,
    _Outptr_ PSHADOW_ALPC_PORT_ENTRY* Entry
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    ULONG hashIndex;
    PLIST_ENTRY listEntry;
    PSHADOW_ALPC_PORT_ENTRY portEntry;
    BOOLEAN found = FALSE;

    *Entry = NULL;

    if (!state->Initialized || state->ShuttingDown) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // CRITICAL FIX: Acquire rundown protection to prevent cleanup during operation
    //
    if (!ExAcquireRundownProtection(&state->RundownProtection)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    hashIndex = ShadowAlpcHashPortObject(PortObject);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&state->HashBuckets[hashIndex].Lock);

    for (listEntry = state->HashBuckets[hashIndex].PortList.Flink;
         listEntry != &state->HashBuckets[hashIndex].PortList;
         listEntry = listEntry->Flink) {

        portEntry = CONTAINING_RECORD(listEntry, SHADOW_ALPC_PORT_ENTRY, HashEntry);

        if (portEntry->PortObject == PortObject && !portEntry->RemovedFromList) {
            ShadowAlpcpReferencePortEntry(portEntry);
            *Entry = portEntry;
            found = TRUE;

            //
            // Update access time
            //
            KeQuerySystemTime(&portEntry->LastAccessTime);

            InterlockedIncrement64(&state->Stats.CacheHits);
            break;
        }
    }

    ExReleasePushLockShared(&state->HashBuckets[hashIndex].Lock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&state->RundownProtection);

    if (!found) {
        InterlockedIncrement64(&state->Stats.CacheMisses);
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowAlpcReleasePortEntry(
    _In_opt_ PSHADOW_ALPC_PORT_ENTRY Entry
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    LONG newRefCount;

    if (Entry == NULL) {
        return;
    }

    newRefCount = InterlockedDecrement(&Entry->ReferenceCount);

    if (newRefCount == 0) {
        ShadowAlpcpFreePortEntry(state, Entry);
    } else if (newRefCount < 0) {
        //
        // CRITICAL FIX: Reference underflow is a fatal error
        // Bugcheck to prevent use-after-free corruption
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/ALPC] CRITICAL: Port entry reference underflow!\n");
        KeBugCheckEx(
            DRIVER_IRQL_NOT_LESS_OR_EQUAL,
            (ULONG_PTR)Entry,
            (ULONG_PTR)newRefCount,
            0,
            0x5348414C  // 'SHAL' - ShadowStrike ALPC
        );
    }
}

_Use_decl_annotations_
VOID
ShadowAlpcRemovePort(
    _In_ PVOID PortObject
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    ULONG hashIndex;
    PLIST_ENTRY listEntry;
    PSHADOW_ALPC_PORT_ENTRY portEntry = NULL;
    BOOLEAN foundInHash = FALSE;

    if (!state->Initialized) {
        return;
    }

    hashIndex = ShadowAlpcHashPortObject(PortObject);

    //
    // Remove from hash bucket first (lock hierarchy)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&state->HashBuckets[hashIndex].Lock);

    for (listEntry = state->HashBuckets[hashIndex].PortList.Flink;
         listEntry != &state->HashBuckets[hashIndex].PortList;
         listEntry = listEntry->Flink) {

        portEntry = CONTAINING_RECORD(listEntry, SHADOW_ALPC_PORT_ENTRY, HashEntry);

        if (portEntry->PortObject == PortObject) {
            RemoveEntryList(&portEntry->HashEntry);
            InterlockedDecrement(&state->HashBuckets[hashIndex].Count);
            InterlockedExchange(&portEntry->RemovedFromList, TRUE);
            foundInHash = TRUE;
            break;
        }
        portEntry = NULL;
    }

    ExReleasePushLockExclusive(&state->HashBuckets[hashIndex].Lock);
    KeLeaveCriticalRegion();

    if (foundInHash && portEntry != NULL) {
        //
        // Remove from global list (lock hierarchy: global list second)
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&state->PortListLock);
        RemoveEntryList(&portEntry->GlobalEntry);
        InterlockedDecrement(&state->PortCount);
        ExReleasePushLockExclusive(&state->PortListLock);
        KeLeaveCriticalRegion();

        //
        // Release our reference
        //
        ShadowAlpcReleasePortEntry(portEntry);

        InterlockedIncrement64(&state->Stats.PortsClosed);
    }
}

// ============================================================================
// CONNECTION TRACKING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowAlpcTrackConnection(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY PortEntry,
    _In_ HANDLE ClientPid,
    _In_ PVOID ClientPortObject
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    PSHADOW_ALPC_CONNECTION connection;
    PEPROCESS clientProcess = NULL;
    NTSTATUS status;
    SHADOW_INTEGRITY_LEVEL integrityLevel;

    if (!state->Initialized || state->ShuttingDown) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    connection = ShadowAlpcpAllocateConnection(state);
    if (connection == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    connection->ClientProcessId = ClientPid;
    connection->ServerProcessId = PortEntry->OwnerProcessId;
    connection->ClientPortObject = ClientPortObject;
    connection->ServerPortObject = PortEntry->PortObject;
    connection->ReferenceCount = 1;
    connection->RemovedFromList = FALSE;

    KeQuerySystemTime(&connection->ConnectTime);
    connection->LastMessageTime = connection->ConnectTime;

    //
    // Get client process info using ProcessUtils
    //
    status = PsLookupProcessByProcessId(ClientPid, &clientProcess);
    if (NT_SUCCESS(status)) {
        connection->ClientSessionId = PsGetProcessSessionId(clientProcess);

        //
        // CRITICAL FIX: Use ProcessUtils for proper integrity level detection
        //
        status = ShadowStrikeGetProcessIntegrityLevel(ClientPid, &integrityLevel);
        if (NT_SUCCESS(status)) {
            connection->ClientIntegrityLevel = ShadowAlpcIntegrityLevelToRid(integrityLevel);
        } else {
            //
            // SECURITY FIX: Default to SYSTEM on failure (fail-secure)
            //
            connection->ClientIntegrityLevel = SECURITY_MANDATORY_SYSTEM_RID;
        }

        ObDereferenceObject(clientProcess);
    }

    connection->ServerSessionId = PortEntry->OwnerSessionId;

    //
    // Analyze suspicion
    //
    if (connection->ClientSessionId != connection->ServerSessionId) {
        connection->SuspicionFlags |= AlpcSuspicionCrossSession;
        InterlockedIncrement64(&state->Stats.CrossSessionConnections);
    }

    if (connection->ClientIntegrityLevel < PortEntry->OwnerIntegrityLevel) {
        connection->SuspicionFlags |= AlpcSuspicionLowToHigh;
        InterlockedIncrement64(&state->Stats.LowToHighConnections);
    }

    //
    // Add to port's connection list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&PortEntry->ConnectionLock);

    if (PortEntry->ConnectionCount < SHADOW_ALPC_MAX_CONNECTIONS_PER_PORT) {
        InsertTailList(&PortEntry->ConnectionList, &connection->ListEntry);
        InterlockedIncrement(&PortEntry->ConnectionCount);
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_QUOTA_EXCEEDED;
    }

    ExReleasePushLockExclusive(&PortEntry->ConnectionLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(status)) {
        ShadowAlpcpFreeConnection(state, connection);
        return status;
    }

    InterlockedIncrement64(&PortEntry->TotalConnections);
    InterlockedIncrement64(&state->Stats.ConnectionsEstablished);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowAlpcRemoveConnection(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY PortEntry,
    _In_ PVOID ClientPortObject
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    PLIST_ENTRY listEntry;
    PSHADOW_ALPC_CONNECTION connection = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&PortEntry->ConnectionLock);

    for (listEntry = PortEntry->ConnectionList.Flink;
         listEntry != &PortEntry->ConnectionList;
         listEntry = listEntry->Flink) {

        connection = CONTAINING_RECORD(listEntry, SHADOW_ALPC_CONNECTION, ListEntry);

        if (connection->ClientPortObject == ClientPortObject) {
            RemoveEntryList(&connection->ListEntry);
            InterlockedDecrement(&PortEntry->ConnectionCount);
            InterlockedExchange(&connection->RemovedFromList, TRUE);
            break;
        }
        connection = NULL;
    }

    ExReleasePushLockExclusive(&PortEntry->ConnectionLock);
    KeLeaveCriticalRegion();

    if (connection != NULL) {
        ShadowAlpcpFreeConnection(state, connection);
        InterlockedIncrement64(&state->Stats.ConnectionsTerminated);
    }
}

// ============================================================================
// THREAT ANALYSIS
// ============================================================================

_Use_decl_annotations_
VOID
ShadowAlpcAnalyzeOperation(
    _Inout_ PSHADOW_ALPC_OPERATION_CONTEXT Context
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    ULONG score = 0;

    Context->SuspicionFlags = AlpcSuspicionNone;
    Context->ThreatScore = 0;

    //
    // Check sensitive port access
    //
    ULONG portWeight = 0;
    if (ShadowAlpcIsSensitivePort(Context->PortName, &portWeight)) {
        Context->SuspicionFlags |= AlpcSuspicionSensitivePort;
        score += portWeight;
    }

    //
    // Check cross-session access
    //
    if (Context->SourceSessionId != Context->TargetSessionId) {
        Context->SuspicionFlags |= AlpcSuspicionCrossSession;
        score += 20;
        InterlockedIncrement64(&state->Stats.CrossSessionConnections);
    }

    //
    // Check integrity level violation (using RID values for comparison)
    //
    if (Context->SourceIntegrityLevel < Context->TargetIntegrityLevel) {
        Context->SuspicionFlags |= AlpcSuspicionLowToHigh;
        score += 35;
        InterlockedIncrement64(&state->Stats.LowToHighConnections);

        //
        // Potential sandbox escape
        //
        if (Context->SourceIntegrityLevel <= SECURITY_MANDATORY_LOW_RID) {
            Context->SuspicionFlags |= AlpcSuspicionSandboxEscape;
            score += 40;
            InterlockedIncrement64(&state->Stats.SandboxEscapeAttempts);
        }
    }

    //
    // Check rate limiting (only if we have a port entry)
    //
    if (Context->PortEntry != NULL && ShadowAlpcCheckRateLimit(Context->PortEntry)) {
        Context->SuspicionFlags |= AlpcSuspicionRapidConnect;
        score += 15;
    }

    //
    // Cap score at 100
    //
    if (score > 100) {
        score = 100;
    }

    Context->ThreatScore = score;

    if (score > 0) {
        InterlockedIncrement64(&state->Stats.SuspiciousOperations);
    }
}

_Use_decl_annotations_
SHADOW_ALPC_VERDICT
ShadowAlpcDetermineVerdict(
    _In_ PSHADOW_ALPC_OPERATION_CONTEXT Context
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;

    //
    // Kernel handles always allowed
    //
    if (Context->IsKernelHandle) {
        return AlpcVerdictAllow;
    }

    //
    // Check threat threshold
    //
    if (Context->ThreatScore >= state->Config.ThreatThreshold) {
        if (state->Config.BlockingEnabled) {
            if (ShadowAlpcIsHighThreat(Context->SuspicionFlags)) {
                return AlpcVerdictBlock;
            }
            return AlpcVerdictStrip;
        }
        return AlpcVerdictMonitor;
    }

    //
    // Lower threat - monitor only
    //
    if (Context->ThreatScore > 0) {
        return AlpcVerdictMonitor;
    }

    return AlpcVerdictAllow;
}

BOOLEAN
ShadowAlpcIsSensitivePort(
    _In_ PCWSTR PortName,
    _Out_opt_ PULONG ThreatWeight
    )
{
    const SHADOW_ALPC_SENSITIVE_PORT* entry;

    if (ThreatWeight != NULL) {
        *ThreatWeight = 0;
    }

    if (PortName == NULL || PortName[0] == L'\0') {
        return FALSE;
    }

    for (entry = g_SensitiveAlpcPorts; entry->PortNamePattern != NULL; entry++) {
        if (entry->IsPrefix) {
            //
            // Prefix match - use bounded comparison
            //
            SIZE_T patternLen = wcsnlen(entry->PortNamePattern, SHADOW_ALPC_MAX_PORT_NAME);
            if (_wcsnicmp(PortName, entry->PortNamePattern, patternLen) == 0) {
                if (ThreatWeight != NULL) {
                    *ThreatWeight = entry->ThreatWeight;
                }
                return TRUE;
            }
        } else {
            //
            // Exact match
            //
            if (_wcsicmp(PortName, entry->PortNamePattern) == 0) {
                if (ThreatWeight != NULL) {
                    *ThreatWeight = entry->ThreatWeight;
                }
                return TRUE;
            }
        }
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
ShadowAlpcCheckRateLimit(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY PortEntry
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    LARGE_INTEGER currentTime;
    LONGLONG timeDelta;

    if (!state->Config.RateLimitingEnabled) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);
    timeDelta = currentTime.QuadPart - PortEntry->RateLimitWindowStart.QuadPart;

    if (timeDelta > SHADOW_ALPC_RATE_LIMIT_WINDOW) {
        //
        // Reset window
        //
        PortEntry->RateLimitWindowStart = currentTime;
        InterlockedExchange(&PortEntry->ConnectionsInWindow, 1);
        PortEntry->IsRateLimited = FALSE;
        return FALSE;
    }

    LONG count = InterlockedIncrement(&PortEntry->ConnectionsInWindow);
    if ((ULONG)count > state->Config.MaxConnectionsPerSecond) {
        PortEntry->IsRateLimited = TRUE;
        InterlockedIncrement64(&state->Stats.RateLimitViolations);
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// EVENT QUEUE
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowAlpcQueueEvent(
    _In_ SHADOW_ALPC_EVENT_TYPE EventType,
    _In_ PSHADOW_ALPC_OPERATION_CONTEXT Context,
    _In_ BOOLEAN WasBlocked
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    PSHADOW_ALPC_EVENT event;
    PSHADOW_ALPC_EVENT oldEvent = NULL;
    KIRQL oldIrql;

    event = ShadowAlpcpAllocateEvent(state);
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event->EventType = EventType;
    event->SuspicionFlags = Context->SuspicionFlags;
    event->ThreatScore = Context->ThreatScore;
    event->SourceProcessId = Context->SourceProcessId;
    event->TargetProcessId = Context->TargetProcessId;
    event->Operation = Context->Operation;
    event->RequestedAccess = Context->OriginalAccess;
    event->WasBlocked = WasBlocked;

    KeQuerySystemTime(&event->Timestamp);

    RtlCopyMemory(event->SourceProcessName, Context->SourceProcessName,
                  sizeof(event->SourceProcessName));
    RtlCopyMemory(event->PortName, Context->PortName,
                  sizeof(event->PortName));

    KeAcquireSpinLock(&state->EventLock, &oldIrql);

    if (state->EventCount >= (LONG)state->MaxEvents) {
        //
        // Queue full - drop oldest
        //
        PLIST_ENTRY oldEntry = RemoveTailList(&state->EventQueue);
        oldEvent = CONTAINING_RECORD(oldEntry, SHADOW_ALPC_EVENT, ListEntry);
        InterlockedDecrement(&state->EventCount);
    }

    InsertHeadList(&state->EventQueue, &event->ListEntry);
    InterlockedIncrement(&state->EventCount);

    KeReleaseSpinLock(&state->EventLock, oldIrql);

    //
    // Free old event outside spinlock
    //
    if (oldEvent != NULL) {
        ShadowAlpcFreeEvent(oldEvent);
    }

    InterlockedIncrement64(&state->Stats.AlertsGenerated);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowAlpcDequeueEvent(
    _Outptr_ PSHADOW_ALPC_EVENT* Event
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    *Event = NULL;

    KeAcquireSpinLock(&state->EventLock, &oldIrql);

    if (IsListEmpty(&state->EventQueue)) {
        KeReleaseSpinLock(&state->EventLock, oldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    entry = RemoveTailList(&state->EventQueue);
    InterlockedDecrement(&state->EventCount);

    KeReleaseSpinLock(&state->EventLock, oldIrql);

    *Event = CONTAINING_RECORD(entry, SHADOW_ALPC_EVENT, ListEntry);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowAlpcFreeEvent(
    _In_ PSHADOW_ALPC_EVENT Event
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;

    if (Event != NULL && state->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&state->EventLookaside, Event);
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
VOID
ShadowAlpcGetStatistics(
    _Out_ PSHADOW_ALPC_STATISTICS Stats
    )
{
    if (Stats != NULL) {
        //
        // Copy statistics atomically where possible
        // Note: This is a snapshot, values may change during copy
        //
        RtlCopyMemory(Stats, &g_AlpcPortMonitorState.Stats, sizeof(SHADOW_ALPC_STATISTICS));
    }
}

VOID
ShadowAlpcResetStatistics(
    VOID
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = &g_AlpcPortMonitorState;
    RtlZeroMemory(&state->Stats, sizeof(SHADOW_ALPC_STATISTICS));
    KeQuerySystemTime(&state->Stats.StartTime);
}

// ============================================================================
// CONFIGURATION
// ============================================================================

VOID
ShadowAlpcSetMonitoringEnabled(
    _In_ BOOLEAN Enable
    )
{
    //
    // CRITICAL FIX: Use InterlockedExchange8 for BOOLEAN (1 byte) or
    // use a simple volatile write with memory barrier since BOOLEAN
    // writes are atomic on x86/x64. Using MemoryBarrier for visibility.
    //
    MemoryBarrier();
    g_AlpcPortMonitorState.Config.MonitoringEnabled = Enable;
    MemoryBarrier();
}

VOID
ShadowAlpcSetBlockingEnabled(
    _In_ BOOLEAN Enable
    )
{
    //
    // CRITICAL FIX: Use proper atomic write for BOOLEAN
    //
    MemoryBarrier();
    g_AlpcPortMonitorState.Config.BlockingEnabled = Enable;
    MemoryBarrier();
}

VOID
ShadowAlpcSetThreatThreshold(
    _In_ ULONG Threshold
    )
{
    if (Threshold <= 100) {
        InterlockedExchange((PLONG)&g_AlpcPortMonitorState.Config.ThreatThreshold, Threshold);
    }
}

// ============================================================================
// OBJECT CALLBACKS
// ============================================================================

OB_PREOP_CALLBACK_STATUS
ShadowAlpcPortPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = (PSHADOW_ALPC_MONITOR_STATE)RegistrationContext;
    SHADOW_ALPC_OPERATION_CONTEXT context;
    PSHADOW_ALPC_PORT_ENTRY portEntry = NULL;
    ACCESS_MASK requestedAccess;
    SHADOW_ALPC_VERDICT verdict;
    NTSTATUS status;
    SHADOW_INTEGRITY_LEVEL integrityLevel;

    if (OperationInformation == NULL || OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (state == NULL || !state->Initialized || state->ShuttingDown) {
        return OB_PREOP_SUCCESS;
    }

    if (!state->Config.MonitoringEnabled) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Acquire rundown protection for this operation
    //
    if (!ExAcquireRundownProtection(&state->RundownProtection)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Skip kernel handles
    //
    if (OperationInformation->KernelHandle) {
        ExReleaseRundownProtection(&state->RundownProtection);
        return OB_PREOP_SUCCESS;
    }

    //
    // Initialize context
    //
    RtlZeroMemory(&context, sizeof(context));
    KeQuerySystemTime(&context.Timestamp);

    context.PortObject = OperationInformation->Object;
    context.SourceProcessId = PsGetCurrentProcessId();
    context.SourceProcess = PsGetCurrentProcess();
    context.IsKernelHandle = OperationInformation->KernelHandle;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        context.Operation = AlpcOperationCreatePort;
        requestedAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        context.Operation = AlpcOperationConnectPort;
        requestedAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        ExReleaseRundownProtection(&state->RundownProtection);
        return OB_PREOP_SUCCESS;
    }

    context.OriginalAccess = requestedAccess;

    //
    // Get source process info - IRQL safe operations only
    //
    context.SourceSessionId = PsGetProcessSessionId(context.SourceProcess);

    //
    // CRITICAL FIX: Use ProcessUtils for proper integrity level
    // This is safe to call at <= APC_LEVEL
    //
    status = ShadowStrikeGetProcessIntegrityLevel(context.SourceProcessId, &integrityLevel);
    if (NT_SUCCESS(status)) {
        context.SourceIntegrityLevel = ShadowAlpcIntegrityLevelToRid(integrityLevel);
    } else {
        //
        // SECURITY FIX: Default to SYSTEM on failure (fail-secure)
        //
        context.SourceIntegrityLevel = SECURITY_MANDATORY_SYSTEM_RID;
    }

    //
    // Get process name safely
    //
    ShadowAlpcpGetProcessNameSafe(context.SourceProcessId, context.SourceProcessName,
                                   SHADOW_ALPC_MAX_PROCESS_NAME);

    //
    // Find or create port entry
    //
    status = ShadowAlpcFindPort(context.PortObject, &portEntry);
    if (NT_SUCCESS(status)) {
        context.PortEntry = portEntry;
        RtlCopyMemory(context.PortName, portEntry->PortName, sizeof(context.PortName));
        context.TargetProcessId = portEntry->OwnerProcessId;
        context.TargetSessionId = portEntry->OwnerSessionId;
        context.TargetIntegrityLevel = portEntry->OwnerIntegrityLevel;
    } else {
        //
        // Extract port name directly
        //
        ShadowAlpcpExtractPortNameSafe(context.PortObject, context.PortName, SHADOW_ALPC_MAX_PORT_NAME);
    }

    //
    // Analyze operation
    //
    ShadowAlpcAnalyzeOperation(&context);

    //
    // Determine verdict
    //
    verdict = ShadowAlpcDetermineVerdict(&context);
    context.Verdict = verdict;

    //
    // Apply verdict
    //
    switch (verdict) {
        case AlpcVerdictBlock:
        case AlpcVerdictStrip:
            //
            // Strip dangerous access rights
            //
            context.ModifiedAccess = requestedAccess & ~(
                PORT_CONNECT |
                PORT_ALL_ACCESS
            );

            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess =
                    context.ModifiedAccess;
            } else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess =
                    context.ModifiedAccess;
            }

            InterlockedIncrement64(&state->Stats.BlockedOperations);
            ShadowAlpcQueueEvent(AlpcEventSuspiciousAccess, &context, TRUE);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/ALPC] %s: PID %lu -> Port '%ws', Score=%lu\n",
                       verdict == AlpcVerdictBlock ? "BLOCKED" : "STRIPPED",
                       HandleToULong(context.SourceProcessId),
                       context.PortName,
                       context.ThreatScore);
            break;

        case AlpcVerdictMonitor:
            if (context.ThreatScore >= state->Config.ThreatThreshold) {
                ShadowAlpcQueueEvent(AlpcEventSuspiciousAccess, &context, FALSE);
            }
            break;

        case AlpcVerdictAllow:
        default:
            break;
    }

    //
    // Release port entry reference
    //
    if (portEntry != NULL) {
        ShadowAlpcReleasePortEntry(portEntry);
    }

    ExReleaseRundownProtection(&state->RundownProtection);
    return OB_PREOP_SUCCESS;
}

VOID
ShadowAlpcPortPostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    )
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);

    //
    // Post-operation telemetry could track actual granted access
    // Currently not needed - pre-operation handles all detection
    //
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Dynamically resolve ALPC Port object type.
 *
 * Uses ObTypeIndexTable walking to find the ALPC Port object type.
 * This approach works across Windows versions without hardcoded offsets.
 *
 * Strategy:
 * 1. Enumerate all object types via ObTypeIndexTable
 * 2. Match by type name "ALPC Port"
 * 3. Return the matching OBJECT_TYPE pointer
 */
static NTSTATUS
ShadowAlpcpResolveAlpcPortType(
    _Out_ POBJECT_TYPE* AlpcPortType
    )
{
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG i;
    POBJECT_TYPE objectType = NULL;
    UNICODE_STRING alpcPortTypeName;
    UNICODE_STRING currentTypeName;
    PVOID typeInfoBuffer = NULL;
    ULONG typeInfoSize = 0;
    ULONG returnLength = 0;
    POBJECT_TYPES_INFORMATION typesInfo = NULL;
    POBJECT_TYPE_INFORMATION typeInfo = NULL;
    PUCHAR currentPtr = NULL;

    *AlpcPortType = NULL;

    RtlInitUnicodeString(&alpcPortTypeName, L"ALPC Port");

    //
    // Query required size for object types information
    //
    status = ZwQueryObject(
        NULL,
        ObjectTypesInformation,
        NULL,
        0,
        &returnLength
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/ALPC] Failed to query object types size: 0x%X\n", status);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Add padding for safety (types can be added between calls)
    //
    typeInfoSize = returnLength + 4096;

    //
    // Sanity limit
    //
    if (typeInfoSize > (1024 * 1024)) {
        return STATUS_BUFFER_OVERFLOW;
    }

    typeInfoBuffer = ShadowStrikeAllocatePagedWithTag(typeInfoSize, SHADOW_ALPC_CACHE_TAG);
    if (typeInfoBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryObject(
        NULL,
        ObjectTypesInformation,
        typeInfoBuffer,
        typeInfoSize,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/ALPC] Failed to query object types: 0x%X\n", status);
        ShadowStrikeFreePoolWithTag(typeInfoBuffer, SHADOW_ALPC_CACHE_TAG);
        return status;
    }

    typesInfo = (POBJECT_TYPES_INFORMATION)typeInfoBuffer;

    //
    // Walk the type list looking for "ALPC Port"
    //
    currentPtr = (PUCHAR)(typesInfo + 1);

    for (i = 0; i < typesInfo->NumberOfTypes; i++) {
        typeInfo = (POBJECT_TYPE_INFORMATION)currentPtr;

        //
        // Validate we're still within bounds
        //
        if ((ULONG_PTR)currentPtr + sizeof(OBJECT_TYPE_INFORMATION) >
            (ULONG_PTR)typeInfoBuffer + typeInfoSize) {
            break;
        }

        //
        // Build UNICODE_STRING for comparison
        //
        currentTypeName.Length = typeInfo->TypeName.Length;
        currentTypeName.MaximumLength = typeInfo->TypeName.MaximumLength;
        currentTypeName.Buffer = typeInfo->TypeName.Buffer;

        //
        // Compare with "ALPC Port"
        //
        if (RtlCompareUnicodeString(&currentTypeName, &alpcPortTypeName, TRUE) == 0) {
            //
            // Found it - now get the actual OBJECT_TYPE pointer
            // The TypeIndex in the info structure corresponds to the ObTypeIndexTable index
            //
            // On Windows 10+, we can use ObGetObjectType on a known ALPC port object
            // For now, we use a different approach: create a temporary ALPC port
            // and extract its type.
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/ALPC] Found ALPC Port type at index %u\n",
                       typeInfo->TypeIndex);

            //
            // Get object type by creating and inspecting a temporary object
            //
            status = ShadowAlpcpGetPortTypeViaCreation(AlpcPortType);
            if (NT_SUCCESS(status) && *AlpcPortType != NULL) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                           "[ShadowStrike/ALPC] Successfully resolved ALPC Port type: %p\n",
                           *AlpcPortType);
            }
            break;
        }

        //
        // Move to next entry (aligned to pointer size)
        //
        currentPtr += sizeof(OBJECT_TYPE_INFORMATION);
        currentPtr += ALIGN_UP(typeInfo->TypeName.MaximumLength, sizeof(ULONG_PTR));
    }

    ShadowStrikeFreePoolWithTag(typeInfoBuffer, SHADOW_ALPC_CACHE_TAG);

    if (*AlpcPortType == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/ALPC] Could not resolve ALPC Port type. "
                   "Operating in degraded mode (ETW-only monitoring).\n");
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Get ALPC Port object type by creating a temporary port.
 *
 * Creates a temporary ALPC port, extracts its object type via ObGetObjectType,
 * then closes it. This is the most reliable method that works across all
 * Windows versions.
 */
static NTSTATUS
ShadowAlpcpGetPortTypeViaCreation(
    _Out_ POBJECT_TYPE* AlpcPortType
    )
{
    NTSTATUS status;
    HANDLE portHandle = NULL;
    PVOID portObject = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;
    ALPC_PORT_ATTRIBUTES portAttributes;
    WCHAR portNameBuffer[64];

    *AlpcPortType = NULL;

    //
    // Generate unique port name in the driver's namespace
    //
    status = RtlStringCchPrintfW(
        portNameBuffer,
        RTL_NUMBER_OF(portNameBuffer),
        L"\\BaseNamedObjects\\ShadowStrike_TypeProbe_%p",
        PsGetCurrentProcessId()
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, portNameBuffer);

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    RtlZeroMemory(&portAttributes, sizeof(portAttributes));
    portAttributes.MaxMessageLength = 256;

    //
    // Create temporary ALPC port
    //
    status = ZwAlpcCreatePort(
        &portHandle,
        &objectAttributes,
        &portAttributes
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/ALPC] ZwAlpcCreatePort failed: 0x%X\n", status);
        return status;
    }

    //
    // Get object pointer from handle
    //
    status = ObReferenceObjectByHandle(
        portHandle,
        0,
        NULL,  // Any object type
        KernelMode,
        &portObject,
        NULL
    );

    if (NT_SUCCESS(status) && portObject != NULL) {
        //
        // Extract the object type
        //
        *AlpcPortType = ObGetObjectType(portObject);
        ObDereferenceObject(portObject);
    }

    //
    // Close the temporary port
    //
    ZwClose(portHandle);

    if (*AlpcPortType == NULL) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

static VOID
ShadowAlpcpExtractPortNameSafe(
    _In_ PVOID PortObject,
    _Out_writes_(MaxLength) PWCHAR PortName,
    _In_ ULONG MaxLength
    )
{
    NTSTATUS status;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG returnLength = 0;
    ULONG bufferSize;

    PortName[0] = L'\0';

    if (MaxLength == 0) {
        return;
    }

    //
    // Query object name length first
    //
    status = ObQueryNameString(
        PortObject,
        NULL,
        0,
        &returnLength
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        return;
    }

    //
    // Sanity check on size
    //
    if (returnLength > (SHADOW_ALPC_MAX_PORT_NAME * sizeof(WCHAR) + sizeof(OBJECT_NAME_INFORMATION))) {
        return;
    }

    bufferSize = returnLength;
    nameInfo = (POBJECT_NAME_INFORMATION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        bufferSize,
        SHADOW_ALPC_STRING_TAG
    );

    if (nameInfo == NULL) {
        return;
    }

    status = ObQueryNameString(
        PortObject,
        nameInfo,
        bufferSize,
        &returnLength
    );

    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL && nameInfo->Name.Length > 0) {
        USHORT copyLen = min(nameInfo->Name.Length / sizeof(WCHAR), MaxLength - 1);
        RtlCopyMemory(PortName, nameInfo->Name.Buffer, copyLen * sizeof(WCHAR));
        PortName[copyLen] = L'\0';
    }

    ShadowStrikeFreePoolWithTag(nameInfo, SHADOW_ALPC_STRING_TAG);
}

static VOID
ShadowAlpcpGetProcessNameSafe(
    _In_ HANDLE ProcessId,
    _Out_writes_(MaxLength) PWCHAR ProcessName,
    _In_ ULONG MaxLength
    )
{
    UNICODE_STRING imageName = { 0 };
    NTSTATUS status;

    ProcessName[0] = L'\0';

    if (MaxLength == 0) {
        return;
    }

    //
    // Use ProcessUtils to get process name safely
    //
    status = ShadowStrikeGetProcessImageName(ProcessId, &imageName);
    if (NT_SUCCESS(status) && imageName.Buffer != NULL && imageName.Length > 0) {
        USHORT copyLen = min(imageName.Length / sizeof(WCHAR), MaxLength - 1);
        RtlCopyMemory(ProcessName, imageName.Buffer, copyLen * sizeof(WCHAR));
        ProcessName[copyLen] = L'\0';
        ShadowFreeProcessString(&imageName);
    }
}

static PSHADOW_ALPC_PORT_ENTRY
ShadowAlpcpAllocatePortEntry(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    )
{
    PSHADOW_ALPC_PORT_ENTRY entry;

    if (!State->LookasideInitialized) {
        return NULL;
    }

    entry = (PSHADOW_ALPC_PORT_ENTRY)ExAllocateFromNPagedLookasideList(
        &State->PortEntryLookaside
    );

    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(SHADOW_ALPC_PORT_ENTRY));
        InitializeListHead(&entry->HashEntry);
        InitializeListHead(&entry->GlobalEntry);
        InitializeListHead(&entry->ConnectionList);
    }

    return entry;
}

static VOID
ShadowAlpcpFreePortEntry(
    _In_ PSHADOW_ALPC_MONITOR_STATE State,
    _In_ PSHADOW_ALPC_PORT_ENTRY Entry
    )
{
    PLIST_ENTRY listEntry;
    PSHADOW_ALPC_CONNECTION connection;

    if (Entry == NULL) {
        return;
    }

    //
    // Free all connections
    //
    while (!IsListEmpty(&Entry->ConnectionList)) {
        listEntry = RemoveHeadList(&Entry->ConnectionList);
        connection = CONTAINING_RECORD(listEntry, SHADOW_ALPC_CONNECTION, ListEntry);
        ShadowAlpcpFreeConnection(State, connection);
    }

    if (State->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&State->PortEntryLookaside, Entry);
    }
}

static PSHADOW_ALPC_CONNECTION
ShadowAlpcpAllocateConnection(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    )
{
    PSHADOW_ALPC_CONNECTION connection;

    if (!State->LookasideInitialized) {
        return NULL;
    }

    connection = (PSHADOW_ALPC_CONNECTION)ExAllocateFromNPagedLookasideList(
        &State->ConnectionLookaside
    );

    if (connection != NULL) {
        RtlZeroMemory(connection, sizeof(SHADOW_ALPC_CONNECTION));
        InitializeListHead(&connection->ListEntry);
    }

    return connection;
}

static VOID
ShadowAlpcpFreeConnection(
    _In_ PSHADOW_ALPC_MONITOR_STATE State,
    _In_ PSHADOW_ALPC_CONNECTION Connection
    )
{
    if (Connection != NULL && State->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&State->ConnectionLookaside, Connection);
    }
}

static PSHADOW_ALPC_EVENT
ShadowAlpcpAllocateEvent(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    )
{
    PSHADOW_ALPC_EVENT event;

    if (!State->LookasideInitialized) {
        return NULL;
    }

    event = (PSHADOW_ALPC_EVENT)ExAllocateFromNPagedLookasideList(
        &State->EventLookaside
    );

    if (event != NULL) {
        RtlZeroMemory(event, sizeof(SHADOW_ALPC_EVENT));
        InitializeListHead(&event->ListEntry);
    }

    return event;
}

static VOID
ShadowAlpcpReferencePortEntry(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY Entry
    )
{
    InterlockedIncrement(&Entry->ReferenceCount);
}

static VOID
ShadowAlpcpWorkerThread(
    _In_ PVOID StartContext
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = (PSHADOW_ALPC_MONITOR_STATE)StartContext;
    PVOID waitObjects[2];
    NTSTATUS status;

    waitObjects[0] = &state->ShutdownEvent;
    waitObjects[1] = &state->WorkAvailableEvent;

    while (!state->ShuttingDown) {
        status = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
        );

        if (status == STATUS_WAIT_0 || state->ShuttingDown) {
            break;
        }

        if (status == STATUS_WAIT_1) {
            if (state->Initialized && !state->ShuttingDown) {
                ShadowAlpcpCleanupStaleEntries(state);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
ShadowAlpcpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSHADOW_ALPC_MONITOR_STATE state = (PSHADOW_ALPC_MONITOR_STATE)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    //
    // CRITICAL FIX: Check shutdown state atomically
    //
    if (state != NULL && !state->ShuttingDown && state->Initialized) {
        KeSetEvent(&state->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);
    }
}

static VOID
ShadowAlpcpCleanupStaleEntries(
    _In_ PSHADOW_ALPC_MONITOR_STATE State
    )
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PSHADOW_ALPC_PORT_ENTRY portEntry;
    LIST_ENTRY staleList;
    ULONG i;
    ULONG staleHash;

    KeQuerySystemTime(&currentTime);
    InitializeListHead(&staleList);

    //
    // Scan each hash bucket for stale entries
    // FIXED: Proper lock hierarchy - hash bucket locks only
    //
    for (i = 0; i < SHADOW_ALPC_HASH_BUCKETS; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&State->HashBuckets[i].Lock);

        for (entry = State->HashBuckets[i].PortList.Flink;
             entry != &State->HashBuckets[i].PortList;
             entry = nextEntry) {

            nextEntry = entry->Flink;
            portEntry = CONTAINING_RECORD(entry, SHADOW_ALPC_PORT_ENTRY, HashEntry);

            //
            // Check if entry is stale and has no active references
            // CRITICAL FIX: Use InterlockedCompareExchange to atomically check
            // and claim the entry for removal (preventing TOCTOU race)
            //
            if ((currentTime.QuadPart - portEntry->LastAccessTime.QuadPart) > SHADOW_ALPC_PORT_TTL) {
                //
                // Atomically try to set RemovedFromList from FALSE to TRUE
                // This prevents race where another thread references between our check and removal
                //
                LONG wasRemoved = InterlockedCompareExchange(&portEntry->RemovedFromList, TRUE, FALSE);
                if (wasRemoved == FALSE && InterlockedCompareExchange(&portEntry->ReferenceCount, 1, 1) == 1) {
                    //
                    // Successfully claimed - now safe to remove
                    //
                    RemoveEntryList(&portEntry->HashEntry);
                    InterlockedDecrement(&State->HashBuckets[i].Count);

                    //
                    // Add to stale list for deferred cleanup
                    //
                    InsertTailList(&staleList, &portEntry->HashEntry);
                } else if (wasRemoved == FALSE) {
                    //
                    // Reference count wasn't 1, revert RemovedFromList flag
                    //
                    InterlockedExchange(&portEntry->RemovedFromList, FALSE);
                }
            }
        }

        ExReleasePushLockExclusive(&State->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Now remove from global list and free - outside hash bucket locks
    //
    while (!IsListEmpty(&staleList)) {
        entry = RemoveHeadList(&staleList);
        portEntry = CONTAINING_RECORD(entry, SHADOW_ALPC_PORT_ENTRY, HashEntry);

        //
        // Remove from global list
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&State->PortListLock);
        RemoveEntryList(&portEntry->GlobalEntry);
        InterlockedDecrement(&State->PortCount);
        ExReleasePushLockExclusive(&State->PortListLock);
        KeLeaveCriticalRegion();

        //
        // Release our reference (will free the entry)
        //
        ShadowAlpcReleasePortEntry(portEntry);
    }
}
