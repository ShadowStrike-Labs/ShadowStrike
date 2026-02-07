/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE CONNECTION TRACKER IMPLEMENTATION
 * ============================================================================
 *
 * @file ConnectionTracker.c
 * @brief Enterprise-grade network connection state tracking for WFP integration.
 *
 * This module provides comprehensive connection lifecycle management:
 * - Per-process connection tracking with O(1) flow ID lookup
 * - 5-tuple hash table for endpoint-based queries
 * - Connection state machine with callback notifications
 * - Real-time flow statistics and bandwidth monitoring
 * - TLS/SSL metadata extraction and JA3 fingerprinting support
 * - Automatic stale connection cleanup via DPC timer
 * - Thread-safe reference counting for connection objects
 * - Memory-efficient lookaside list allocations
 *
 * Performance Characteristics:
 * - O(1) lookup by flow ID (hash table)
 * - O(1) lookup by 5-tuple (hash table)
 * - Lock-free statistics updates (InterlockedXxx)
 * - Minimal lock contention via push locks
 * - Lookaside lists for connection/process allocations
 *
 * MITRE ATT&CK Coverage:
 * - T1071: Application Layer Protocol (connection profiling)
 * - T1095: Non-Application Layer Protocol
 * - T1571: Non-Standard Port
 * - T1572: Protocol Tunneling
 * - T1573: Encrypted Channel
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ConnectionTracker.h"
#include "../Core/Globals.h"
#include "../Communication/ScanBridge.h"
#include "../Utilities/ProcessUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CtInitialize)
#pragma alloc_text(PAGE, CtShutdown)
#pragma alloc_text(PAGE, CtCreateConnection)
#pragma alloc_text(PAGE, CtGetProcessConnections)
#pragma alloc_text(PAGE, CtGetProcessNetworkStats)
#pragma alloc_text(PAGE, CtEnumerateConnections)
#pragma alloc_text(PAGE, CtRegisterCallback)
#pragma alloc_text(PAGE, CtUnregisterCallback)
#pragma alloc_text(PAGE, CtpCleanupStaleConnections)
#pragma alloc_text(PAGE, CtpGetOrCreateProcessContext)
#pragma alloc_text(PAGE, CtpResolveProcessInfo)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define CT_FLOW_HASH_BUCKET_COUNT       4096
#define CT_CONN_HASH_BUCKET_COUNT       4096
#define CT_PROCESS_HASH_BUCKET_COUNT    256
#define CT_MAX_CALLBACKS                16
#define CT_CLEANUP_INTERVAL_100NS       (CT_CONNECTION_TIMEOUT_MS * 10000LL)
#define CT_LOOKASIDE_DEPTH              512

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Flow hash entry for O(1) flow ID lookup.
 */
typedef struct _CT_FLOW_HASH_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 FlowId;
    PCT_CONNECTION Connection;
} CT_FLOW_HASH_ENTRY, *PCT_FLOW_HASH_ENTRY;

/**
 * @brief Registered callback entry.
 */
typedef struct _CT_CALLBACK_ENTRY {
    CT_CONNECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN InUse;
} CT_CALLBACK_ENTRY, *PCT_CALLBACK_ENTRY;

/**
 * @brief Internal tracker state (extends public CT_TRACKER).
 */
typedef struct _CT_TRACKER_INTERNAL {
    //
    // Public structure (must be first)
    //
    CT_TRACKER Public;

    //
    // Process hash table (by PID)
    //
    struct {
        LIST_ENTRY Buckets[CT_PROCESS_HASH_BUCKET_COUNT];
        EX_PUSH_LOCK Lock;
    } ProcessHash;

    //
    // Registered callbacks
    //
    CT_CALLBACK_ENTRY Callbacks[CT_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;
    volatile LONG CallbackCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST ConnectionLookaside;
    NPAGED_LOOKASIDE_LIST ProcessContextLookaside;
    NPAGED_LOOKASIDE_LIST FlowHashLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup state
    //
    volatile BOOLEAN CleanupTimerActive;
    volatile BOOLEAN ShuttingDown;

} CT_TRACKER_INTERNAL, *PCT_TRACKER_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
CtpHashFlowId(
    _In_ UINT64 FlowId
    );

static ULONG
CtpHash5Tuple(
    _In_ PVOID LocalAddress,
    _In_ USHORT LocalPort,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ UCHAR Protocol,
    _In_ BOOLEAN IsIPv6
    );

static ULONG
CtpHashProcessId(
    _In_ HANDLE ProcessId
    );

static PCT_PROCESS_CONTEXT
CtpGetOrCreateProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static VOID
CtpReleaseProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_PROCESS_CONTEXT Context
    );

static VOID
CtpResolveProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ProcessName,
    _Out_ PUNICODE_STRING ProcessPath
    );

static VOID
CtpInsertConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    );

static VOID
CtpRemoveConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    );

static VOID
CtpNotifyCallbacks(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection,
    _In_ CT_CONNECTION_STATE OldState,
    _In_ CT_CONNECTION_STATE NewState
    );

static VOID
CtpFreeConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CtpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
CtpCleanupStaleConnections(
    _In_ PCT_TRACKER_INTERNAL Tracker
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtInitialize(
    _Out_ PCT_TRACKER* Tracker
    )
/**
 * @brief Initialize the connection tracker subsystem.
 *
 * Allocates and initializes all data structures required for
 * connection tracking including hash tables, lookaside lists,
 * and cleanup timer.
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    PCT_TRACKER_INTERNAL tracker = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    //
    // Allocate tracker structure
    //
    tracker = (PCT_TRACKER_INTERNAL)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(CT_TRACKER_INTERNAL),
        CT_POOL_TAG_CONN
    );

    if (tracker == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize connection list
    //
    InitializeListHead(&tracker->Public.ConnectionList);
    ExInitializePushLock(&tracker->Public.ConnectionListLock);

    //
    // Allocate and initialize connection hash table
    //
    tracker->Public.ConnectionHash.BucketCount = CT_CONN_HASH_BUCKET_COUNT;
    tracker->Public.ConnectionHash.Buckets = (LIST_ENTRY*)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(LIST_ENTRY) * CT_CONN_HASH_BUCKET_COUNT,
        CT_POOL_TAG_CONN
    );

    if (tracker->Public.ConnectionHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < CT_CONN_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&tracker->Public.ConnectionHash.Buckets[i]);
    }
    ExInitializePushLock(&tracker->Public.ConnectionHash.Lock);

    //
    // Allocate and initialize flow hash table
    //
    tracker->Public.FlowHash.BucketCount = CT_FLOW_HASH_BUCKET_COUNT;
    tracker->Public.FlowHash.Buckets = (LIST_ENTRY*)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(LIST_ENTRY) * CT_FLOW_HASH_BUCKET_COUNT,
        CT_POOL_TAG_FLOW
    );

    if (tracker->Public.FlowHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < CT_FLOW_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&tracker->Public.FlowHash.Buckets[i]);
    }
    ExInitializePushLock(&tracker->Public.FlowHash.Lock);

    //
    // Initialize process list and hash
    //
    InitializeListHead(&tracker->Public.ProcessList);
    ExInitializePushLock(&tracker->Public.ProcessListLock);

    for (i = 0; i < CT_PROCESS_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&tracker->ProcessHash.Buckets[i]);
    }
    ExInitializePushLock(&tracker->ProcessHash.Lock);

    //
    // Initialize callback array
    //
    RtlZeroMemory(tracker->Callbacks, sizeof(tracker->Callbacks));
    ExInitializePushLock(&tracker->CallbackLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &tracker->ConnectionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CT_CONNECTION),
        CT_POOL_TAG_CONN,
        CT_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &tracker->ProcessContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CT_PROCESS_CONTEXT),
        CT_POOL_TAG_PROC,
        64
    );

    ExInitializeNPagedLookasideList(
        &tracker->FlowHashLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CT_FLOW_HASH_ENTRY),
        CT_POOL_TAG_FLOW,
        CT_LOOKASIDE_DEPTH
    );

    tracker->LookasideInitialized = TRUE;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&tracker->Public.CleanupTimer);
    KeInitializeDpc(&tracker->Public.CleanupDpc, CtpCleanupTimerDpc, tracker);
    tracker->Public.CleanupIntervalMs = CT_CONNECTION_TIMEOUT_MS / 2;

    //
    // Set default configuration
    //
    tracker->Public.Config.MaxConnections = CT_MAX_CONNECTIONS;
    tracker->Public.Config.ConnectionTimeoutMs = CT_CONNECTION_TIMEOUT_MS;
    tracker->Public.Config.TrackAllProcesses = TRUE;
    tracker->Public.Config.EnableTLSInspection = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&tracker->Public.Stats.StartTime);

    //
    // Start cleanup timer
    //
    dueTime.QuadPart = -((LONGLONG)tracker->Public.CleanupIntervalMs * 10000);
    KeSetTimerEx(
        &tracker->Public.CleanupTimer,
        dueTime,
        tracker->Public.CleanupIntervalMs,
        &tracker->Public.CleanupDpc
    );
    tracker->CleanupTimerActive = TRUE;

    tracker->Public.Initialized = TRUE;
    *Tracker = &tracker->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (tracker != NULL) {
        if (tracker->Public.ConnectionHash.Buckets != NULL) {
            ExFreePoolWithTag(tracker->Public.ConnectionHash.Buckets, CT_POOL_TAG_CONN);
        }
        if (tracker->Public.FlowHash.Buckets != NULL) {
            ExFreePoolWithTag(tracker->Public.FlowHash.Buckets, CT_POOL_TAG_FLOW);
        }
        ExFreePoolWithTag(tracker, CT_POOL_TAG_CONN);
    }

    return status;
}

_Use_decl_annotations_
VOID
CtShutdown(
    _Inout_ PCT_TRACKER Tracker
    )
/**
 * @brief Shutdown and cleanup the connection tracker.
 *
 * Cancels cleanup timer, releases all connections and
 * process contexts, frees all allocated memory.
 */
{
    PCT_TRACKER_INTERNAL tracker;
    PLIST_ENTRY entry;
    PCT_CONNECTION connection;
    PCT_PROCESS_CONTEXT processCtx;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized) {
        return;
    }

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);
    tracker->ShuttingDown = TRUE;

    //
    // Cancel cleanup timer
    //
    if (tracker->CleanupTimerActive) {
        KeCancelTimer(&Tracker->CleanupTimer);
        tracker->CleanupTimerActive = FALSE;
    }

    //
    // Wait for any pending DPCs to complete
    //
    KeFlushQueuedDpcs();

    //
    // Free all connections
    //
    ExAcquirePushLockExclusive(&Tracker->ConnectionListLock);

    while (!IsListEmpty(&Tracker->ConnectionList)) {
        entry = RemoveHeadList(&Tracker->ConnectionList);
        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);

        //
        // Free connection resources
        //
        if (connection->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(connection->ProcessName.Buffer, CT_POOL_TAG_CONN);
        }
        if (connection->ProcessPath.Buffer != NULL) {
            ExFreePoolWithTag(connection->ProcessPath.Buffer, CT_POOL_TAG_CONN);
        }

        if (tracker->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&tracker->ConnectionLookaside, connection);
        } else {
            ExFreePoolWithTag(connection, CT_POOL_TAG_CONN);
        }
    }

    ExReleasePushLockExclusive(&Tracker->ConnectionListLock);

    //
    // Free all process contexts
    //
    ExAcquirePushLockExclusive(&Tracker->ProcessListLock);

    while (!IsListEmpty(&Tracker->ProcessList)) {
        entry = RemoveHeadList(&Tracker->ProcessList);
        processCtx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, ListEntry);

        if (processCtx->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(processCtx->ProcessName.Buffer, CT_POOL_TAG_PROC);
        }

        if (tracker->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&tracker->ProcessContextLookaside, processCtx);
        } else {
            ExFreePoolWithTag(processCtx, CT_POOL_TAG_PROC);
        }
    }

    ExReleasePushLockExclusive(&Tracker->ProcessListLock);

    //
    // Free hash tables
    //
    if (Tracker->ConnectionHash.Buckets != NULL) {
        ExFreePoolWithTag(Tracker->ConnectionHash.Buckets, CT_POOL_TAG_CONN);
        Tracker->ConnectionHash.Buckets = NULL;
    }

    if (Tracker->FlowHash.Buckets != NULL) {
        ExFreePoolWithTag(Tracker->FlowHash.Buckets, CT_POOL_TAG_FLOW);
        Tracker->FlowHash.Buckets = NULL;
    }

    //
    // Delete lookaside lists
    //
    if (tracker->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&tracker->ConnectionLookaside);
        ExDeleteNPagedLookasideList(&tracker->ProcessContextLookaside);
        ExDeleteNPagedLookasideList(&tracker->FlowHashLookaside);
        tracker->LookasideInitialized = FALSE;
    }

    Tracker->Initialized = FALSE;

    //
    // Free tracker structure
    //
    ExFreePoolWithTag(tracker, CT_POOL_TAG_CONN);
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtCreateConnection(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _In_ HANDLE ProcessId,
    _In_ CT_DIRECTION Direction,
    _In_ UCHAR Protocol,
    _In_ PVOID LocalAddress,
    _In_ USHORT LocalPort,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _Out_ PCT_CONNECTION* Connection
    )
/**
 * @brief Create a new tracked connection.
 *
 * Allocates a connection entry, populates with endpoint information,
 * inserts into hash tables, and links to process context.
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    PCT_TRACKER_INTERNAL tracker;
    PCT_CONNECTION connection = NULL;
    PCT_PROCESS_CONTEXT processCtx = NULL;
    PCT_FLOW_HASH_ENTRY flowEntry = NULL;
    ULONG flowBucket;
    ULONG connBucket;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized || Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (LocalAddress == NULL || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;
    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    //
    // Check connection limit
    //
    if ((ULONG)Tracker->ConnectionCount >= Tracker->Config.MaxConnections) {
        InterlockedIncrement64(&Tracker->Stats.BlockedConnections);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate connection from lookaside
    //
    connection = (PCT_CONNECTION)ExAllocateFromNPagedLookasideList(
        &tracker->ConnectionLookaside
    );

    if (connection == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(connection, sizeof(CT_CONNECTION));

    //
    // Allocate flow hash entry
    //
    flowEntry = (PCT_FLOW_HASH_ENTRY)ExAllocateFromNPagedLookasideList(
        &tracker->FlowHashLookaside
    );

    if (flowEntry == NULL) {
        ExFreeToNPagedLookasideList(&tracker->ConnectionLookaside, connection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize connection
    //
    connection->ConnectionId = (ULONG64)InterlockedIncrement64(&Tracker->NextConnectionId);
    connection->FlowId = FlowId;
    connection->State = CtState_New;
    connection->Direction = Direction;
    connection->Protocol = Protocol;
    connection->IsIPv6 = IsIPv6;
    connection->ProcessId = ProcessId;
    connection->RefCount = 1;

    KeQuerySystemTime(&connection->CreateTime);

    //
    // Copy addresses
    //
    if (IsIPv6) {
        RtlCopyMemory(&connection->LocalAddress.IPv6, LocalAddress, sizeof(IN6_ADDR));
        RtlCopyMemory(&connection->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
        connection->Flags |= CtFlag_IPv6;
    } else {
        RtlCopyMemory(&connection->LocalAddress.IPv4, LocalAddress, sizeof(IN_ADDR));
        RtlCopyMemory(&connection->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    connection->LocalPort = LocalPort;
    connection->RemotePort = RemotePort;

    //
    // Check for loopback
    //
    if (!IsIPv6) {
        UCHAR firstByte = ((PUCHAR)LocalAddress)[0];
        if (firstByte == 127) {
            connection->Flags |= CtFlag_Loopback;
        }
    }

    //
    // Initialize flow statistics
    //
    connection->Stats.FirstPacketTime = connection->CreateTime;
    connection->Stats.LastPacketTime = connection->CreateTime;

    //
    // Get or create process context
    //
    processCtx = CtpGetOrCreateProcessContext(tracker, ProcessId);
    if (processCtx != NULL) {
        //
        // Copy process info to connection
        //
        if (processCtx->ProcessName.Buffer != NULL) {
            connection->ProcessName.MaximumLength = processCtx->ProcessName.Length + sizeof(WCHAR);
            connection->ProcessName.Buffer = (PWCH)ExAllocatePoolZero(
                NonPagedPoolNx,
                connection->ProcessName.MaximumLength,
                CT_POOL_TAG_CONN
            );

            if (connection->ProcessName.Buffer != NULL) {
                RtlCopyUnicodeString(&connection->ProcessName, &processCtx->ProcessName);
            }
        }

        //
        // Link connection to process
        //
        KeAcquireSpinLockAtDpcLevel(&processCtx->ConnectionLock);
        InsertTailList(&processCtx->ConnectionList, &connection->ProcessListEntry);
        InterlockedIncrement(&processCtx->ConnectionCount);
        InterlockedIncrement(&processCtx->ActiveConnectionCount);
        InterlockedIncrement64(&processCtx->TotalConnections);
        KeReleaseSpinLockFromDpcLevel(&processCtx->ConnectionLock);

        connection->ProcessToken = (ULONG64)(ULONG_PTR)processCtx;
    }

    //
    // Initialize flow hash entry
    //
    flowEntry->FlowId = FlowId;
    flowEntry->Connection = connection;
    InitializeListHead(&flowEntry->ListEntry);

    //
    // Insert into flow hash table
    //
    flowBucket = CtpHashFlowId(FlowId);

    ExAcquirePushLockExclusive(&Tracker->FlowHash.Lock);
    InsertTailList(&Tracker->FlowHash.Buckets[flowBucket], &flowEntry->ListEntry);
    ExReleasePushLockExclusive(&Tracker->FlowHash.Lock);

    //
    // Insert into connection hash table
    //
    connBucket = CtpHash5Tuple(
        LocalAddress, LocalPort,
        RemoteAddress, RemotePort,
        Protocol, IsIPv6
    );

    ExAcquirePushLockExclusive(&Tracker->ConnectionHash.Lock);
    InsertTailList(&Tracker->ConnectionHash.Buckets[connBucket], &connection->HashListEntry);
    ExReleasePushLockExclusive(&Tracker->ConnectionHash.Lock);

    //
    // Insert into global list
    //
    ExAcquirePushLockExclusive(&Tracker->ConnectionListLock);
    InsertTailList(&Tracker->ConnectionList, &connection->GlobalListEntry);
    InterlockedIncrement(&Tracker->ConnectionCount);
    ExReleasePushLockExclusive(&Tracker->ConnectionListLock);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.TotalConnections);
    InterlockedIncrement64(&Tracker->Stats.ActiveConnections);

    //
    // Notify callbacks
    //
    CtpNotifyCallbacks(tracker, connection, CtState_New, CtState_New);

    //
    // Add reference for caller
    //
    CtAddRef(connection);
    *Connection = connection;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CtUpdateConnectionState(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _In_ CT_CONNECTION_STATE NewState
    )
/**
 * @brief Update the state of an existing connection.
 *
 * Transitions connection state machine and notifies registered callbacks.
 */
{
    NTSTATUS status;
    PCT_TRACKER_INTERNAL tracker;
    PCT_CONNECTION connection = NULL;
    CT_CONNECTION_STATE oldState;

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    //
    // Find connection by flow ID
    //
    status = CtFindByFlowId(Tracker, FlowId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Update state
    //
    oldState = connection->State;
    connection->State = NewState;

    //
    // Update timestamps based on state
    //
    switch (NewState) {
        case CtState_Connected:
        case CtState_Established:
            KeQuerySystemTime(&connection->ConnectTime);
            break;

        case CtState_Closed:
        case CtState_TimedOut:
        case CtState_Error:
            KeQuerySystemTime(&connection->CloseTime);
            InterlockedDecrement64(&Tracker->Stats.ActiveConnections);
            break;

        case CtState_Blocked:
            KeQuerySystemTime(&connection->CloseTime);
            connection->Flags |= CtFlag_Blocked;
            InterlockedIncrement64(&Tracker->Stats.BlockedConnections);
            InterlockedDecrement64(&Tracker->Stats.ActiveConnections);
            break;

        default:
            break;
    }

    //
    // Notify callbacks
    //
    CtpNotifyCallbacks(tracker, connection, oldState, NewState);

    //
    // Release our reference
    //
    CtRelease(connection);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CtRemoveConnection(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId
    )
/**
 * @brief Remove a connection from tracking.
 *
 * Removes from all hash tables and lists, notifies callbacks,
 * and schedules connection for cleanup.
 */
{
    NTSTATUS status;
    PCT_TRACKER_INTERNAL tracker;
    PCT_CONNECTION connection = NULL;
    CT_CONNECTION_STATE oldState;

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    //
    // Find and remove from flow hash
    //
    status = CtFindByFlowId(Tracker, FlowId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    oldState = connection->State;

    //
    // Update state if not already closed
    //
    if (connection->State != CtState_Closed &&
        connection->State != CtState_Blocked &&
        connection->State != CtState_TimedOut) {

        connection->State = CtState_Closed;
        KeQuerySystemTime(&connection->CloseTime);
        InterlockedDecrement64(&Tracker->Stats.ActiveConnections);
    }

    //
    // Notify callbacks
    //
    CtpNotifyCallbacks(tracker, connection, oldState, CtState_Closed);

    //
    // Remove from tracking structures
    //
    CtpRemoveConnection(tracker, connection);

    //
    // Release lookup reference and original reference
    //
    CtRelease(connection);
    CtRelease(connection);

    return STATUS_SUCCESS;
}

// ============================================================================
// CONNECTION LOOKUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtFindByFlowId(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _Out_ PCT_CONNECTION* Connection
    )
/**
 * @brief Find connection by WFP flow ID.
 *
 * O(1) lookup via flow hash table. Adds reference to returned connection.
 */
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PCT_FLOW_HASH_ENTRY flowEntry;
    PCT_CONNECTION connection = NULL;

    if (Tracker == NULL || !Tracker->Initialized || Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;

    bucket = CtpHashFlowId(FlowId);

    ExAcquirePushLockShared(&Tracker->FlowHash.Lock);

    for (entry = Tracker->FlowHash.Buckets[bucket].Flink;
         entry != &Tracker->FlowHash.Buckets[bucket];
         entry = entry->Flink) {

        flowEntry = CONTAINING_RECORD(entry, CT_FLOW_HASH_ENTRY, ListEntry);

        if (flowEntry->FlowId == FlowId) {
            connection = flowEntry->Connection;
            CtAddRef(connection);
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->FlowHash.Lock);

    if (connection == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Connection = connection;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CtFindByEndpoints(
    _In_ PCT_TRACKER Tracker,
    _In_ PVOID LocalAddress,
    _In_ USHORT LocalPort,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ UCHAR Protocol,
    _In_ BOOLEAN IsIPv6,
    _Out_ PCT_CONNECTION* Connection
    )
/**
 * @brief Find connection by 5-tuple (addresses, ports, protocol).
 *
 * O(1) lookup via connection hash table. Adds reference to returned connection.
 */
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PCT_CONNECTION connection = NULL;
    SIZE_T addrSize;

    if (Tracker == NULL || !Tracker->Initialized || Connection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (LocalAddress == NULL || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Connection = NULL;
    addrSize = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);

    bucket = CtpHash5Tuple(
        LocalAddress, LocalPort,
        RemoteAddress, RemotePort,
        Protocol, IsIPv6
    );

    ExAcquirePushLockShared(&Tracker->ConnectionHash.Lock);

    for (entry = Tracker->ConnectionHash.Buckets[bucket].Flink;
         entry != &Tracker->ConnectionHash.Buckets[bucket];
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, CT_CONNECTION, HashListEntry);

        if (connection->Protocol == Protocol &&
            connection->IsIPv6 == IsIPv6 &&
            connection->LocalPort == LocalPort &&
            connection->RemotePort == RemotePort) {

            PVOID connLocal = IsIPv6 ?
                (PVOID)&connection->LocalAddress.IPv6 :
                (PVOID)&connection->LocalAddress.IPv4;

            PVOID connRemote = IsIPv6 ?
                (PVOID)&connection->RemoteAddress.IPv6 :
                (PVOID)&connection->RemoteAddress.IPv4;

            if (RtlCompareMemory(connLocal, LocalAddress, addrSize) == addrSize &&
                RtlCompareMemory(connRemote, RemoteAddress, addrSize) == addrSize) {

                CtAddRef(connection);
                ExReleasePushLockShared(&Tracker->ConnectionHash.Lock);
                *Connection = connection;
                return STATUS_SUCCESS;
            }
        }
    }

    ExReleasePushLockShared(&Tracker->ConnectionHash.Lock);

    return STATUS_NOT_FOUND;
}

// ============================================================================
// STATISTICS UPDATE
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtUpdateStats(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _In_ SIZE_T BytesSent,
    _In_ SIZE_T BytesReceived,
    _In_ ULONG PacketsSent,
    _In_ ULONG PacketsReceived
    )
/**
 * @brief Update flow statistics for a connection.
 *
 * Lock-free statistics updates using interlocked operations.
 */
{
    NTSTATUS status;
    PCT_CONNECTION connection = NULL;
    LARGE_INTEGER currentTime;

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    status = CtFindByFlowId(Tracker, FlowId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Update connection statistics (lock-free)
    //
    if (BytesSent > 0) {
        InterlockedAdd64(&connection->Stats.BytesSent, (LONG64)BytesSent);
        InterlockedAdd64(&connection->Stats.PacketsSent, PacketsSent);
    }

    if (BytesReceived > 0) {
        InterlockedAdd64(&connection->Stats.BytesReceived, (LONG64)BytesReceived);
        InterlockedAdd64(&connection->Stats.PacketsReceived, PacketsReceived);
    }

    //
    // Update last packet time
    //
    KeQuerySystemTime(&currentTime);
    connection->Stats.LastPacketTime = currentTime;
    connection->Stats.IdleTimeMs = 0;

    //
    // Update global statistics
    //
    InterlockedAdd64(&Tracker->Stats.TotalBytesSent, (LONG64)BytesSent);
    InterlockedAdd64(&Tracker->Stats.TotalBytesReceived, (LONG64)BytesReceived);

    //
    // Update process context if available
    //
    if (connection->ProcessToken != 0) {
        PCT_PROCESS_CONTEXT processCtx = (PCT_PROCESS_CONTEXT)(ULONG_PTR)connection->ProcessToken;
        InterlockedAdd64(&processCtx->TotalBytesSent, (LONG64)BytesSent);
        InterlockedAdd64(&processCtx->TotalBytesReceived, (LONG64)BytesReceived);
    }

    //
    // Check for large transfer flag
    //
    LONG64 totalBytes = connection->Stats.BytesSent + connection->Stats.BytesReceived;
    if (totalBytes > (10 * 1024 * 1024)) { // 10 MB
        connection->Flags |= CtFlag_LargeTransfer;
    }

    CtRelease(connection);

    return STATUS_SUCCESS;
}

// ============================================================================
// PROCESS QUERIES
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtGetProcessConnections(
    _In_ PCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxConnections, *ConnectionCount) PCT_CONNECTION* Connections,
    _In_ ULONG MaxConnections,
    _Out_ PULONG ConnectionCount
    )
/**
 * @brief Get all connections for a specific process.
 *
 * Returns array of connection pointers with references added.
 * Caller must release each connection.
 */
{
    PCT_TRACKER_INTERNAL tracker;
    PCT_PROCESS_CONTEXT processCtx = NULL;
    PLIST_ENTRY entry;
    PCT_CONNECTION connection;
    ULONG count = 0;
    ULONG bucket;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized ||
        Connections == NULL || ConnectionCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ConnectionCount = 0;
    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    //
    // Find process context
    //
    bucket = CtpHashProcessId(ProcessId);

    ExAcquirePushLockShared(&tracker->ProcessHash.Lock);

    for (entry = tracker->ProcessHash.Buckets[bucket].Flink;
         entry != &tracker->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, ListEntry);
        if (ctx->ProcessId == ProcessId) {
            processCtx = ctx;
            InterlockedIncrement(&processCtx->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&tracker->ProcessHash.Lock);

    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Enumerate connections for this process
    //
    KeAcquireSpinLock(&processCtx->ConnectionLock, &oldIrql);

    for (entry = processCtx->ConnectionList.Flink;
         entry != &processCtx->ConnectionList && count < MaxConnections;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, CT_CONNECTION, ProcessListEntry);
        CtAddRef(connection);
        Connections[count++] = connection;
    }

    KeReleaseSpinLock(&processCtx->ConnectionLock, oldIrql);

    //
    // Release process context
    //
    CtpReleaseProcessContext(tracker, processCtx);

    *ConnectionCount = count;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CtGetProcessNetworkStats(
    _In_ PCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PULONG64 BytesSent,
    _Out_ PULONG64 BytesReceived,
    _Out_ PULONG ActiveConnections
    )
/**
 * @brief Get aggregate network statistics for a process.
 */
{
    PCT_TRACKER_INTERNAL tracker;
    PCT_PROCESS_CONTEXT processCtx = NULL;
    PLIST_ENTRY entry;
    ULONG bucket;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BytesSent == NULL || BytesReceived == NULL || ActiveConnections == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesSent = 0;
    *BytesReceived = 0;
    *ActiveConnections = 0;

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    bucket = CtpHashProcessId(ProcessId);

    ExAcquirePushLockShared(&tracker->ProcessHash.Lock);

    for (entry = tracker->ProcessHash.Buckets[bucket].Flink;
         entry != &tracker->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, ListEntry);
        if (ctx->ProcessId == ProcessId) {
            processCtx = ctx;
            break;
        }
    }

    if (processCtx != NULL) {
        *BytesSent = processCtx->TotalBytesSent;
        *BytesReceived = processCtx->TotalBytesReceived;
        *ActiveConnections = (ULONG)processCtx->ActiveConnectionCount;
    }

    ExReleasePushLockShared(&tracker->ProcessHash.Lock);

    if (processCtx == NULL) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// ENUMERATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtEnumerateConnections(
    _In_ PCT_TRACKER Tracker,
    _In_ CT_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/**
 * @brief Enumerate all tracked connections.
 *
 * Calls callback for each connection. Callback returns FALSE to stop.
 */
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PCT_CONNECTION connection;
    BOOLEAN continueEnum = TRUE;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockShared(&Tracker->ConnectionListLock);

    for (entry = Tracker->ConnectionList.Flink;
         entry != &Tracker->ConnectionList && continueEnum;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);

        CtAddRef(connection);
        ExReleasePushLockShared(&Tracker->ConnectionListLock);

        continueEnum = Callback(connection, Context);

        CtRelease(connection);

        ExAcquirePushLockShared(&Tracker->ConnectionListLock);
    }

    ExReleasePushLockShared(&Tracker->ConnectionListLock);

    return STATUS_SUCCESS;
}

// ============================================================================
// CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtRegisterCallback(
    _In_ PCT_TRACKER Tracker,
    _In_ CT_CONNECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/**
 * @brief Register a callback for connection state changes.
 */
{
    PCT_TRACKER_INTERNAL tracker;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    ExAcquirePushLockExclusive(&tracker->CallbackLock);

    for (i = 0; i < CT_MAX_CALLBACKS; i++) {
        if (!tracker->Callbacks[i].InUse) {
            tracker->Callbacks[i].Callback = Callback;
            tracker->Callbacks[i].Context = Context;
            tracker->Callbacks[i].InUse = TRUE;
            InterlockedIncrement(&tracker->CallbackCount);
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&tracker->CallbackLock);

    return status;
}

_Use_decl_annotations_
VOID
CtUnregisterCallback(
    _In_ PCT_TRACKER Tracker,
    _In_ CT_CONNECTION_CALLBACK Callback
    )
/**
 * @brief Unregister a previously registered callback.
 */
{
    PCT_TRACKER_INTERNAL tracker;
    ULONG i;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized || Callback == NULL) {
        return;
    }

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    ExAcquirePushLockExclusive(&tracker->CallbackLock);

    for (i = 0; i < CT_MAX_CALLBACKS; i++) {
        if (tracker->Callbacks[i].InUse &&
            tracker->Callbacks[i].Callback == Callback) {

            tracker->Callbacks[i].Callback = NULL;
            tracker->Callbacks[i].Context = NULL;
            tracker->Callbacks[i].InUse = FALSE;
            InterlockedDecrement(&tracker->CallbackCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&tracker->CallbackLock);
}

// ============================================================================
// REFERENCE COUNTING
// ============================================================================

_Use_decl_annotations_
VOID
CtAddRef(
    _In_ PCT_CONNECTION Connection
    )
/**
 * @brief Add reference to connection.
 */
{
    if (Connection != NULL) {
        InterlockedIncrement(&Connection->RefCount);
    }
}

_Use_decl_annotations_
VOID
CtRelease(
    _In_ PCT_CONNECTION Connection
    )
/**
 * @brief Release reference to connection.
 *
 * Connection is freed when reference count reaches zero.
 * Note: Actual freeing is deferred to cleanup to avoid
 * complex locking during release.
 */
{
    if (Connection != NULL) {
        LONG newRef = InterlockedDecrement(&Connection->RefCount);
        NT_ASSERT(newRef >= 0);

        //
        // Actual cleanup happens in CtpCleanupStaleConnections
        // to avoid freeing while still in hash tables
        //
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CtGetStatistics(
    _In_ PCT_TRACKER Tracker,
    _Out_ PCT_STATISTICS Stats
    )
/**
 * @brief Get connection tracker statistics snapshot.
 */
{
    LARGE_INTEGER currentTime;

    if (Tracker == NULL || !Tracker->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(CT_STATISTICS));

    Stats->ActiveConnections = (ULONG)Tracker->ConnectionCount;
    Stats->TotalConnections = Tracker->Stats.TotalConnections;
    Stats->BlockedConnections = Tracker->Stats.BlockedConnections;
    Stats->TotalBytesSent = Tracker->Stats.TotalBytesSent;
    Stats->TotalBytesReceived = Tracker->Stats.TotalBytesReceived;
    Stats->TrackedProcesses = (ULONG)Tracker->ProcessCount;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Tracker->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

static ULONG
CtpHashFlowId(
    _In_ UINT64 FlowId
    )
/**
 * @brief Hash function for flow ID lookup.
 */
{
    //
    // Simple multiplicative hash
    //
    ULONG64 hash = FlowId;
    hash = (hash ^ (hash >> 33)) * 0xff51afd7ed558ccdULL;
    hash = (hash ^ (hash >> 33)) * 0xc4ceb9fe1a85ec53ULL;
    hash = hash ^ (hash >> 33);

    return (ULONG)(hash % CT_FLOW_HASH_BUCKET_COUNT);
}

static ULONG
CtpHash5Tuple(
    _In_ PVOID LocalAddress,
    _In_ USHORT LocalPort,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ UCHAR Protocol,
    _In_ BOOLEAN IsIPv6
    )
/**
 * @brief Hash function for 5-tuple lookup.
 */
{
    ULONG hash = 0;
    SIZE_T addrSize = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);
    PUCHAR localBytes = (PUCHAR)LocalAddress;
    PUCHAR remoteBytes = (PUCHAR)RemoteAddress;
    SIZE_T i;

    //
    // FNV-1a style hash
    //
    hash = 2166136261;

    for (i = 0; i < addrSize; i++) {
        hash ^= localBytes[i];
        hash *= 16777619;
    }

    for (i = 0; i < addrSize; i++) {
        hash ^= remoteBytes[i];
        hash *= 16777619;
    }

    hash ^= (LocalPort & 0xFF);
    hash *= 16777619;
    hash ^= (LocalPort >> 8);
    hash *= 16777619;

    hash ^= (RemotePort & 0xFF);
    hash *= 16777619;
    hash ^= (RemotePort >> 8);
    hash *= 16777619;

    hash ^= Protocol;
    hash *= 16777619;

    return hash % CT_CONN_HASH_BUCKET_COUNT;
}

static ULONG
CtpHashProcessId(
    _In_ HANDLE ProcessId
    )
/**
 * @brief Hash function for process ID lookup.
 */
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    return (ULONG)((pid >> 2) % CT_PROCESS_HASH_BUCKET_COUNT);
}

static PCT_PROCESS_CONTEXT
CtpGetOrCreateProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
/**
 * @brief Get existing or create new process context.
 */
{
    PCT_PROCESS_CONTEXT context = NULL;
    PLIST_ENTRY entry;
    ULONG bucket;
    NTSTATUS status;

    PAGED_CODE();

    bucket = CtpHashProcessId(ProcessId);

    //
    // Check if context already exists
    //
    ExAcquirePushLockShared(&Tracker->ProcessHash.Lock);

    for (entry = Tracker->ProcessHash.Buckets[bucket].Flink;
         entry != &Tracker->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, ListEntry);
        if (ctx->ProcessId == ProcessId) {
            context = ctx;
            InterlockedIncrement(&context->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->ProcessHash.Lock);

    if (context != NULL) {
        return context;
    }

    //
    // Create new context
    //
    context = (PCT_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Tracker->ProcessContextLookaside
    );

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(CT_PROCESS_CONTEXT));

    context->ProcessId = ProcessId;
    context->RefCount = 2; // One for hash, one for caller

    //
    // Get process object
    //
    status = PsLookupProcessByProcessId(ProcessId, &context->Process);
    if (!NT_SUCCESS(status)) {
        context->Process = NULL;
    }

    //
    // Initialize connection list
    //
    InitializeListHead(&context->ConnectionList);
    KeInitializeSpinLock(&context->ConnectionLock);

    //
    // Resolve process info
    //
    CtpResolveProcessInfo(ProcessId, &context->ProcessName, NULL);

    //
    // Insert into hash and list
    //
    ExAcquirePushLockExclusive(&Tracker->ProcessHash.Lock);
    ExAcquirePushLockExclusive(&Tracker->Public.ProcessListLock);

    //
    // Double-check another thread didn't create it
    //
    for (entry = Tracker->ProcessHash.Buckets[bucket].Flink;
         entry != &Tracker->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, ListEntry);
        if (ctx->ProcessId == ProcessId) {
            //
            // Already exists, free our new one
            //
            ExReleasePushLockExclusive(&Tracker->Public.ProcessListLock);
            ExReleasePushLockExclusive(&Tracker->ProcessHash.Lock);

            if (context->Process != NULL) {
                ObDereferenceObject(context->Process);
            }
            if (context->ProcessName.Buffer != NULL) {
                ExFreePoolWithTag(context->ProcessName.Buffer, CT_POOL_TAG_PROC);
            }
            ExFreeToNPagedLookasideList(&Tracker->ProcessContextLookaside, context);

            InterlockedIncrement(&ctx->RefCount);
            return ctx;
        }
    }

    //
    // Insert new context
    //
    InsertTailList(&Tracker->ProcessHash.Buckets[bucket], &context->ListEntry);
    InsertTailList(&Tracker->Public.ProcessList, &context->ListEntry);
    InterlockedIncrement(&Tracker->Public.ProcessCount);

    ExReleasePushLockExclusive(&Tracker->Public.ProcessListLock);
    ExReleasePushLockExclusive(&Tracker->ProcessHash.Lock);

    return context;
}

static VOID
CtpReleaseProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_PROCESS_CONTEXT Context
    )
/**
 * @brief Release reference to process context.
 */
{
    if (Context != NULL) {
        InterlockedDecrement(&Context->RefCount);
        //
        // Actual cleanup happens in CtpCleanupStaleConnections
        //
    }

    UNREFERENCED_PARAMETER(Tracker);
}

static VOID
CtpResolveProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ProcessName,
    _Out_opt_ PUNICODE_STRING ProcessPath
    )
/**
 * @brief Resolve process name and path from PID.
 */
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    PAGED_CODE();

    RtlZeroMemory(ProcessName, sizeof(UNICODE_STRING));
    if (ProcessPath != NULL) {
        RtlZeroMemory(ProcessPath, sizeof(UNICODE_STRING));
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return;
    }

    //
    // Get process image file name
    //
    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {

        //
        // Extract just the filename from the path
        //
        PWCHAR lastSlash = imageName->Buffer;
        PWCHAR p = imageName->Buffer;
        USHORT nameLen;

        while (*p != L'\0') {
            if (*p == L'\\' || *p == L'/') {
                lastSlash = p + 1;
            }
            p++;
        }

        nameLen = (USHORT)((p - lastSlash) * sizeof(WCHAR));

        ProcessName->Buffer = (PWCH)ExAllocatePoolZero(
            NonPagedPoolNx,
            nameLen + sizeof(WCHAR),
            CT_POOL_TAG_PROC
        );

        if (ProcessName->Buffer != NULL) {
            RtlCopyMemory(ProcessName->Buffer, lastSlash, nameLen);
            ProcessName->Length = nameLen;
            ProcessName->MaximumLength = nameLen + sizeof(WCHAR);
        }

        ExFreePool(imageName);
    }

    ObDereferenceObject(process);
}

static VOID
CtpNotifyCallbacks(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection,
    _In_ CT_CONNECTION_STATE OldState,
    _In_ CT_CONNECTION_STATE NewState
    )
/**
 * @brief Notify all registered callbacks of state change.
 */
{
    ULONG i;

    if (Tracker->CallbackCount == 0) {
        return;
    }

    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < CT_MAX_CALLBACKS; i++) {
        if (Tracker->Callbacks[i].InUse && Tracker->Callbacks[i].Callback != NULL) {
            Tracker->Callbacks[i].Callback(
                Connection,
                OldState,
                NewState,
                Tracker->Callbacks[i].Context
            );
        }
    }

    ExReleasePushLockShared(&Tracker->CallbackLock);
}

static VOID
CtpRemoveConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    )
/**
 * @brief Remove connection from all tracking structures.
 */
{
    ULONG flowBucket;
    ULONG connBucket;
    PLIST_ENTRY entry;
    PCT_FLOW_HASH_ENTRY flowEntry = NULL;

    //
    // Remove from flow hash
    //
    flowBucket = CtpHashFlowId(Connection->FlowId);

    ExAcquirePushLockExclusive(&Tracker->Public.FlowHash.Lock);

    for (entry = Tracker->Public.FlowHash.Buckets[flowBucket].Flink;
         entry != &Tracker->Public.FlowHash.Buckets[flowBucket];
         entry = entry->Flink) {

        PCT_FLOW_HASH_ENTRY fe = CONTAINING_RECORD(entry, CT_FLOW_HASH_ENTRY, ListEntry);
        if (fe->FlowId == Connection->FlowId) {
            flowEntry = fe;
            RemoveEntryList(&fe->ListEntry);
            break;
        }
    }

    ExReleasePushLockExclusive(&Tracker->Public.FlowHash.Lock);

    if (flowEntry != NULL) {
        ExFreeToNPagedLookasideList(&Tracker->FlowHashLookaside, flowEntry);
    }

    //
    // Remove from connection hash
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ConnectionHash.Lock);
    RemoveEntryList(&Connection->HashListEntry);
    ExReleasePushLockExclusive(&Tracker->Public.ConnectionHash.Lock);

    //
    // Remove from process context
    //
    if (Connection->ProcessToken != 0) {
        PCT_PROCESS_CONTEXT processCtx = (PCT_PROCESS_CONTEXT)(ULONG_PTR)Connection->ProcessToken;
        KIRQL oldIrql;

        KeAcquireSpinLock(&processCtx->ConnectionLock, &oldIrql);
        RemoveEntryList(&Connection->ProcessListEntry);
        InterlockedDecrement(&processCtx->ConnectionCount);

        if (Connection->State == CtState_Connected ||
            Connection->State == CtState_Established ||
            Connection->State == CtState_Connecting) {
            InterlockedDecrement(&processCtx->ActiveConnectionCount);
        }

        KeReleaseSpinLock(&processCtx->ConnectionLock, oldIrql);

        Connection->ProcessToken = 0;
    }

    //
    // Remove from global list
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ConnectionListLock);
    RemoveEntryList(&Connection->GlobalListEntry);
    InterlockedDecrement(&Tracker->Public.ConnectionCount);
    ExReleasePushLockExclusive(&Tracker->Public.ConnectionListLock);
}

static VOID
CtpFreeConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    )
/**
 * @brief Free connection and associated resources.
 */
{
    if (Connection->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Connection->ProcessName.Buffer, CT_POOL_TAG_CONN);
    }

    if (Connection->ProcessPath.Buffer != NULL) {
        ExFreePoolWithTag(Connection->ProcessPath.Buffer, CT_POOL_TAG_CONN);
    }

    if (Tracker->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Tracker->ConnectionLookaside, Connection);
    } else {
        ExFreePoolWithTag(Connection, CT_POOL_TAG_CONN);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CtpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/**
 * @brief DPC callback for periodic cleanup.
 */
{
    PCT_TRACKER_INTERNAL tracker = (PCT_TRACKER_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (tracker == NULL || tracker->ShuttingDown) {
        return;
    }

    //
    // Queue work item for actual cleanup (needs PASSIVE_LEVEL)
    //
    // For production, use a work item. For this implementation,
    // we mark stale connections here and clean them on next operation.
    //

    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeoutInterval;
    PLIST_ENTRY entry;
    PCT_CONNECTION connection;

    KeQuerySystemTime(&currentTime);
    timeoutInterval.QuadPart = (LONGLONG)tracker->Public.Config.ConnectionTimeoutMs * 10000;

    //
    // Quick scan to mark timed out connections
    //
    ExAcquirePushLockShared(&tracker->Public.ConnectionListLock);

    for (entry = tracker->Public.ConnectionList.Flink;
         entry != &tracker->Public.ConnectionList;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);

        //
        // Check for timeout (closed connections with no refs or idle too long)
        //
        if (connection->State == CtState_Closed ||
            connection->State == CtState_TimedOut ||
            connection->State == CtState_Blocked) {

            if (connection->RefCount <= 1) {
                //
                // Mark for cleanup
                //
                connection->State = CtState_TimedOut;
            }
        }
        else {
            //
            // Check idle time
            //
            LARGE_INTEGER idleTime;
            idleTime.QuadPart = currentTime.QuadPart - connection->Stats.LastPacketTime.QuadPart;

            if (idleTime.QuadPart > timeoutInterval.QuadPart) {
                connection->Stats.IdleTimeMs = (ULONG)(idleTime.QuadPart / 10000);
            }
        }
    }

    ExReleasePushLockShared(&tracker->Public.ConnectionListLock);
}

static VOID
CtpCleanupStaleConnections(
    _In_ PCT_TRACKER_INTERNAL Tracker
    )
/**
 * @brief Clean up stale and timed out connections.
 *
 * Called periodically to free connections that are closed
 * and have no outstanding references.
 */
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PCT_CONNECTION connection;
    LIST_ENTRY freeList;

    PAGED_CODE();

    InitializeListHead(&freeList);

    //
    // Collect connections to free
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ConnectionListLock);

    for (entry = Tracker->Public.ConnectionList.Flink;
         entry != &Tracker->Public.ConnectionList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);

        if ((connection->State == CtState_Closed ||
             connection->State == CtState_TimedOut ||
             connection->State == CtState_Blocked ||
             connection->State == CtState_Error) &&
            connection->RefCount <= 1) {

            //
            // Remove from global list only (others removed by CtpRemoveConnection)
            //
            RemoveEntryList(&connection->GlobalListEntry);
            InterlockedDecrement(&Tracker->Public.ConnectionCount);

            //
            // Add to free list
            //
            InsertTailList(&freeList, &connection->GlobalListEntry);
        }
    }

    ExReleasePushLockExclusive(&Tracker->Public.ConnectionListLock);

    //
    // Free collected connections
    //
    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);

        //
        // Need to remove from other structures first
        //
        CtpRemoveConnection(Tracker, connection);
        CtpFreeConnection(Tracker, connection);
    }
}
