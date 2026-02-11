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
 * - Automatic stale connection cleanup via work-item-deferred timer
 * - Deterministic reference counting — objects freed on last release
 * - Memory-efficient lookaside list allocations
 *
 * Lock Ordering Hierarchy (see ConnectionTracker.h):
 *   1. ConnectionListLock
 *   2. ConnectionHash.Lock
 *   3. FlowHash.Lock
 *   4. ProcessListLock
 *   5. ProcessHash.Lock
 *   6. CT_PROCESS_CONTEXT.ConnectionLock
 *   7. CallbackLock
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Hardened)
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
#pragma alloc_text(PAGE, CtpCleanupWorkItemRoutine)
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

typedef struct _CT_FLOW_HASH_ENTRY {
    LIST_ENTRY ListEntry;
    UINT64 FlowId;
    PCT_CONNECTION Connection;
} CT_FLOW_HASH_ENTRY, *PCT_FLOW_HASH_ENTRY;

typedef struct _CT_CALLBACK_ENTRY {
    CT_CONNECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN InUse;
} CT_CALLBACK_ENTRY, *PCT_CALLBACK_ENTRY;

typedef struct _CT_TRACKER_INTERNAL {
    //
    // Public structure (must be first for CONTAINING_RECORD)
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
    // Cleanup infrastructure
    //
    volatile BOOLEAN CleanupTimerActive;
    volatile BOOLEAN ShuttingDown;
    WORK_QUEUE_ITEM CleanupWorkQueueItem;
    volatile LONG CleanupWorkItemPending;

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
CtpFreeProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_PROCESS_CONTEXT Context
    );

static VOID
CtpResolveProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ProcessName,
    _Out_opt_ PUNICODE_STRING ProcessPath
    );

static VOID
CtpInsertConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    );

static VOID
CtpRemoveConnectionFromLists(
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
CtpCleanupWorkItemRoutine(
    _In_ PVOID Parameter
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
    // Allocate tracker structure from NonPagedPoolNx
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
    // Initialize cleanup timer and work item.
    // The DPC only queues a work item; all real work runs at PASSIVE_LEVEL.
    //
    KeInitializeTimer(&tracker->Public.CleanupTimer);
    KeInitializeDpc(&tracker->Public.CleanupDpc, CtpCleanupTimerDpc, tracker);
    tracker->Public.CleanupIntervalMs = CT_CONNECTION_TIMEOUT_MS / 2;
    tracker->CleanupWorkItemPending = 0;
    ExInitializeWorkItem(
        &tracker->CleanupWorkQueueItem,
        CtpCleanupWorkItemRoutine,
        tracker
    );

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
        if (tracker->LookasideInitialized) {
            ExDeleteNPagedLookasideList(&tracker->ConnectionLookaside);
            ExDeleteNPagedLookasideList(&tracker->ProcessContextLookaside);
            ExDeleteNPagedLookasideList(&tracker->FlowHashLookaside);
        }
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

    //
    // Signal shutdown — prevents DPC/work item from doing more work
    //
    tracker->ShuttingDown = TRUE;
    MemoryBarrier();

    //
    // Cancel cleanup timer and flush pending DPCs
    //
    if (tracker->CleanupTimerActive) {
        KeCancelTimer(&Tracker->CleanupTimer);
        tracker->CleanupTimerActive = FALSE;
    }
    KeFlushQueuedDpcs();

    //
    // Wait for any pending cleanup work item to drain.
    // After KeFlushQueuedDpcs, no new DPC will fire, so the work item
    // counter can only be 0 or actively running. We spin briefly.
    //
    while (InterlockedCompareExchange(&tracker->CleanupWorkItemPending, 0, 0) != 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all connections — remove from all lists first
    //
    ExAcquirePushLockExclusive(&Tracker->ConnectionListLock);

    while (!IsListEmpty(&Tracker->ConnectionList)) {
        entry = RemoveHeadList(&Tracker->ConnectionList);
        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);

        //
        // Mark as removed so CtpFreeConnection doesn't try to unlink again
        //
        InterlockedOr(&connection->Flags, CtFlag_RemovedFromLists);

        //
        // Release process context reference held by this connection
        //
        if (connection->ProcessContextRef != NULL) {
            CtpReleaseProcessContext(tracker, connection->ProcessContextRef);
            connection->ProcessContextRef = NULL;
        }

        CtpFreeConnection(tracker, connection);
    }

    ExReleasePushLockExclusive(&Tracker->ConnectionListLock);

    //
    // Free all process contexts
    //
    ExAcquirePushLockExclusive(&Tracker->ProcessListLock);

    while (!IsListEmpty(&Tracker->ProcessList)) {
        entry = RemoveHeadList(&Tracker->ProcessList);
        processCtx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, GlobalListEntry);

        CtpFreeProcessContext(tracker, processCtx);
    }

    ExReleasePushLockExclusive(&Tracker->ProcessListLock);

    //
    // Free flow hash entries
    //
    {
        ULONG i;
        ExAcquirePushLockExclusive(&Tracker->FlowHash.Lock);
        for (i = 0; i < Tracker->FlowHash.BucketCount; i++) {
            while (!IsListEmpty(&Tracker->FlowHash.Buckets[i])) {
                entry = RemoveHeadList(&Tracker->FlowHash.Buckets[i]);
                PCT_FLOW_HASH_ENTRY fe = CONTAINING_RECORD(entry, CT_FLOW_HASH_ENTRY, ListEntry);
                ExFreeToNPagedLookasideList(&tracker->FlowHashLookaside, fe);
            }
        }
        ExReleasePushLockExclusive(&Tracker->FlowHash.Lock);
    }

    //
    // Free hash table bucket arrays
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
    // Free tracker structure itself
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
{
    NTSTATUS status = STATUS_SUCCESS;
    PCT_TRACKER_INTERNAL tracker;
    PCT_CONNECTION connection = NULL;
    PCT_PROCESS_CONTEXT processCtx = NULL;
    PCT_FLOW_HASH_ENTRY flowEntry = NULL;
    ULONG flowBucket;
    ULONG connBucket;
    LONG currentCount;
    KIRQL oldIrql;
    BOOLEAN duplicateFlow = FALSE;

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
    // Atomically check and reserve a connection slot to prevent exceeding limit.
    //
    do {
        currentCount = Tracker->ConnectionCount;
        if ((ULONG)currentCount >= Tracker->Config.MaxConnections) {
            InterlockedIncrement64(&Tracker->Stats.BlockedConnections);
            return STATUS_QUOTA_EXCEEDED;
        }
    } while (InterlockedCompareExchange(
                &Tracker->ConnectionCount,
                currentCount + 1,
                currentCount) != currentCount);

    //
    // Allocate connection from lookaside
    //
    connection = (PCT_CONNECTION)ExAllocateFromNPagedLookasideList(
        &tracker->ConnectionLookaside
    );

    if (connection == NULL) {
        InterlockedDecrement(&Tracker->ConnectionCount);
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
        InterlockedDecrement(&Tracker->ConnectionCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize connection (immutable fields)
    //
    connection->ConnectionId = (ULONG64)InterlockedIncrement64(&Tracker->NextConnectionId);
    connection->FlowId = FlowId;
    connection->State = (LONG)CtState_New;
    connection->Direction = Direction;
    connection->Protocol = Protocol;
    connection->IsIPv6 = IsIPv6;
    connection->ProcessId = ProcessId;
    connection->RefCount = 1;  // One reference for being in the tracking lists
    connection->OwnerTracker = Tracker;
    connection->TlsInfo = NULL;

    KeQuerySystemTime(&connection->CreateTime);

    //
    // Copy addresses — caller guarantees kernel-mode pointers
    //
    NT_ASSERT(LocalAddress >= MmSystemRangeStart);
    NT_ASSERT(RemoteAddress >= MmSystemRangeStart);

    if (IsIPv6) {
        RtlCopyMemory(&connection->LocalAddress.IPv6, LocalAddress, sizeof(IN6_ADDR));
        RtlCopyMemory(&connection->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
        InterlockedOr(&connection->Flags, CtFlag_IPv6);
    } else {
        RtlCopyMemory(&connection->LocalAddress.IPv4, LocalAddress, sizeof(IN_ADDR));
        RtlCopyMemory(&connection->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    connection->LocalPort = LocalPort;
    connection->RemotePort = RemotePort;

    //
    // Check for loopback (IPv4 and IPv6)
    //
    if (!IsIPv6) {
        UCHAR firstByte = ((PUCHAR)LocalAddress)[0];
        if (firstByte == 127) {
            InterlockedOr(&connection->Flags, CtFlag_Loopback);
        }
    } else {
        //
        // IPv6 loopback is ::1 (all zeros except last byte = 1)
        //
        static const IN6_ADDR ipv6Loopback = { .u.Byte = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        }};
        if (RtlCompareMemory(&connection->LocalAddress.IPv6, &ipv6Loopback,
                             sizeof(IN6_ADDR)) == sizeof(IN6_ADDR)) {
            InterlockedOr(&connection->Flags, CtFlag_Loopback);
        }
    }

    //
    // Initialize flow statistics
    //
    connection->Stats.FirstPacketTime = connection->CreateTime;
    InterlockedExchange64(&connection->Stats.LastPacketTime, connection->CreateTime.QuadPart);

    //
    // Get or create process context (adds a reference for us)
    //
    processCtx = CtpGetOrCreateProcessContext(tracker, ProcessId);
    if (processCtx != NULL) {
        //
        // Copy process name to connection
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
        // Link connection to process. Use proper KeAcquireSpinLock
        // (we are at PASSIVE_LEVEL, must raise to DISPATCH).
        //
        KeAcquireSpinLock(&processCtx->ConnectionLock, &oldIrql);
        InsertTailList(&processCtx->ConnectionList, &connection->ProcessListEntry);
        InterlockedIncrement(&processCtx->ConnectionCount);
        InterlockedIncrement(&processCtx->ActiveConnectionCount);
        InterlockedIncrement64(&processCtx->TotalConnections);
        KeReleaseSpinLock(&processCtx->ConnectionLock, oldIrql);

        //
        // Hold a reference on the process context for this connection.
        // The caller's reference from CtpGetOrCreateProcessContext is
        // transferred to the connection — no extra addref needed.
        //
        connection->ProcessContextRef = processCtx;
    }

    //
    // Initialize flow hash entry
    //
    flowEntry->FlowId = FlowId;
    flowEntry->Connection = connection;
    InitializeListHead(&flowEntry->ListEntry);

    //
    // Check for duplicate FlowId and insert into flow hash table
    //
    flowBucket = CtpHashFlowId(FlowId);

    ExAcquirePushLockExclusive(&Tracker->FlowHash.Lock);
    {
        PLIST_ENTRY fe;
        for (fe = Tracker->FlowHash.Buckets[flowBucket].Flink;
             fe != &Tracker->FlowHash.Buckets[flowBucket];
             fe = fe->Flink) {

            PCT_FLOW_HASH_ENTRY existing = CONTAINING_RECORD(fe, CT_FLOW_HASH_ENTRY, ListEntry);
            if (existing->FlowId == FlowId) {
                duplicateFlow = TRUE;
                break;
            }
        }

        if (!duplicateFlow) {
            InsertTailList(&Tracker->FlowHash.Buckets[flowBucket], &flowEntry->ListEntry);
        }
    }
    ExReleasePushLockExclusive(&Tracker->FlowHash.Lock);

    if (duplicateFlow) {
        //
        // FlowId already tracked — roll back everything
        //
        if (processCtx != NULL) {
            KeAcquireSpinLock(&processCtx->ConnectionLock, &oldIrql);
            RemoveEntryList(&connection->ProcessListEntry);
            InterlockedDecrement(&processCtx->ConnectionCount);
            InterlockedDecrement(&processCtx->ActiveConnectionCount);
            InterlockedDecrement64(&processCtx->TotalConnections);
            KeReleaseSpinLock(&processCtx->ConnectionLock, oldIrql);
            CtpReleaseProcessContext(tracker, processCtx);
            connection->ProcessContextRef = NULL;
        }
        if (connection->ProcessName.Buffer != NULL) {
            ExFreePoolWithTag(connection->ProcessName.Buffer, CT_POOL_TAG_CONN);
        }
        ExFreeToNPagedLookasideList(&tracker->FlowHashLookaside, flowEntry);
        ExFreeToNPagedLookasideList(&tracker->ConnectionLookaside, connection);
        InterlockedDecrement(&Tracker->ConnectionCount);
        return STATUS_DUPLICATE_OBJECTID;
    }

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
    // Insert into global list (count already incremented atomically above)
    //
    ExAcquirePushLockExclusive(&Tracker->ConnectionListLock);
    InsertTailList(&Tracker->ConnectionList, &connection->GlobalListEntry);
    ExReleasePushLockExclusive(&Tracker->ConnectionListLock);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.TotalConnections);
    InterlockedIncrement64(&Tracker->Stats.ActiveConnections);

    //
    // Notify callbacks (outside all locks)
    //
    CtpNotifyCallbacks(tracker, connection, CtState_New, CtState_New);

    //
    // Add reference for caller (total refcount is now 2: lists + caller)
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
{
    NTSTATUS status;
    PCT_TRACKER_INTERNAL tracker;
    PCT_CONNECTION connection = NULL;
    CT_CONNECTION_STATE oldState;

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    tracker = CONTAINING_RECORD(Tracker, CT_TRACKER_INTERNAL, Public);

    status = CtFindByFlowId(Tracker, FlowId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Atomically swap state
    //
    oldState = (CT_CONNECTION_STATE)InterlockedExchange(&connection->State, (LONG)NewState);

    //
    // Determine if this transition affects active connection count.
    // Only decrement if transitioning FROM an active state TO a terminal state.
    //
    {
        BOOLEAN wasActive = (oldState == CtState_New ||
                             oldState == CtState_Connecting ||
                             oldState == CtState_Connected ||
                             oldState == CtState_Established ||
                             oldState == CtState_Closing);

        BOOLEAN isTerminal = (NewState == CtState_Closed ||
                              NewState == CtState_TimedOut ||
                              NewState == CtState_Error ||
                              NewState == CtState_Blocked);

        if (wasActive && isTerminal) {
            InterlockedDecrement64(&Tracker->Stats.ActiveConnections);
        }
    }

    //
    // Update timestamps based on new state
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
            break;

        case CtState_Blocked:
            KeQuerySystemTime(&connection->CloseTime);
            InterlockedOr(&connection->Flags, CtFlag_Blocked);
            InterlockedIncrement64(&Tracker->Stats.BlockedConnections);
            break;

        default:
            break;
    }

    //
    // Notify callbacks
    //
    CtpNotifyCallbacks(tracker, connection, oldState, NewState);

    //
    // Release lookup reference
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
    // Find connection (adds a reference)
    //
    status = CtFindByFlowId(Tracker, FlowId, &connection);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Read current state. volatile LONG reads are atomic on all
    // Windows-supported architectures for aligned 32-bit values.
    //
    oldState = (CT_CONNECTION_STATE)connection->State;

    if (oldState != CtState_Closed && oldState != CtState_Blocked &&
        oldState != CtState_TimedOut && oldState != CtState_Error) {
        //
        // Transition to Closed and update stats exactly once
        //
        InterlockedExchange(&connection->State, (LONG)CtState_Closed);
        KeQuerySystemTime(&connection->CloseTime);
        InterlockedDecrement64(&Tracker->Stats.ActiveConnections);
    }

    //
    // Notify callbacks before removal
    //
    CtpNotifyCallbacks(tracker, connection, oldState, CtState_Closed);

    //
    // Remove from all tracking structures
    //
    CtpRemoveConnectionFromLists(tracker, connection);

    //
    // Release the lookup reference. The lists reference was already
    // released by CtpRemoveConnectionFromLists via CtRelease.
    //
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
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PCT_CONNECTION conn;
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

        conn = CONTAINING_RECORD(entry, CT_CONNECTION, HashListEntry);

        if (conn->Protocol == Protocol &&
            conn->IsIPv6 == IsIPv6 &&
            conn->LocalPort == LocalPort &&
            conn->RemotePort == RemotePort) {

            PVOID connLocal = IsIPv6 ?
                (PVOID)&conn->LocalAddress.IPv6 :
                (PVOID)&conn->LocalAddress.IPv4;

            PVOID connRemote = IsIPv6 ?
                (PVOID)&conn->RemoteAddress.IPv6 :
                (PVOID)&conn->RemoteAddress.IPv4;

            if (RtlCompareMemory(connLocal, LocalAddress, addrSize) == addrSize &&
                RtlCompareMemory(connRemote, RemoteAddress, addrSize) == addrSize) {

                CtAddRef(conn);
                ExReleasePushLockShared(&Tracker->ConnectionHash.Lock);
                *Connection = conn;
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
    // Update connection statistics (all lock-free via Interlocked)
    //
    if (BytesSent > 0) {
        InterlockedAdd64(&connection->Stats.BytesSent, (LONG64)BytesSent);
        InterlockedAdd64(&connection->Stats.PacketsSent, (LONG64)PacketsSent);
    }

    if (BytesReceived > 0) {
        InterlockedAdd64(&connection->Stats.BytesReceived, (LONG64)BytesReceived);
        InterlockedAdd64(&connection->Stats.PacketsReceived, (LONG64)PacketsReceived);
    }

    //
    // Atomically update last packet time (safe for 32-bit and 64-bit)
    //
    KeQuerySystemTime(&currentTime);
    InterlockedExchange64(&connection->Stats.LastPacketTime, currentTime.QuadPart);
    InterlockedExchange(&connection->Stats.IdleTimeMs, 0);

    //
    // Update global statistics
    //
    InterlockedAdd64(&Tracker->Stats.TotalBytesSent, (LONG64)BytesSent);
    InterlockedAdd64(&Tracker->Stats.TotalBytesReceived, (LONG64)BytesReceived);

    //
    // Update process context if available (referenced pointer — safe)
    //
    {
        PCT_PROCESS_CONTEXT processCtx = connection->ProcessContextRef;
        if (processCtx != NULL) {
            InterlockedAdd64(&processCtx->TotalBytesSent, (LONG64)BytesSent);
            InterlockedAdd64(&processCtx->TotalBytesReceived, (LONG64)BytesReceived);
        }
    }

    //
    // Check for large transfer flag (atomic flag set)
    //
    {
        LONG64 totalBytes = connection->Stats.BytesSent + connection->Stats.BytesReceived;
        if (totalBytes > (10LL * 1024 * 1024)) {
            InterlockedOr(&connection->Flags, CtFlag_LargeTransfer);
        }
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

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, HashListEntry);
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
    // Enumerate connections for this process under spin lock
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
    // Release process context reference
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

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, HashListEntry);
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
{
    PCT_CONNECTION* snapshot = NULL;
    ULONG count;
    ULONG capacity;
    ULONG i;
    PLIST_ENTRY entry;
    PCT_CONNECTION connection;

    PAGED_CODE();

    if (Tracker == NULL || !Tracker->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Build a snapshot of connection pointers under the lock,
    // then invoke callbacks outside the lock. This eliminates
    // the use-after-free race of the old design.
    //

    ExAcquirePushLockShared(&Tracker->ConnectionListLock);

    count = (ULONG)Tracker->ConnectionCount;
    if (count == 0) {
        ExReleasePushLockShared(&Tracker->ConnectionListLock);
        return STATUS_SUCCESS;
    }

    capacity = count;

    //
    // Allocate snapshot array. Using NonPagedPoolNx because we hold
    // a push lock (APC_LEVEL). Pool allocation is safe at APC_LEVEL.
    //
    snapshot = (PCT_CONNECTION*)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PCT_CONNECTION) * capacity,
        CT_POOL_TAG_SNAP
    );

    if (snapshot == NULL) {
        ExReleasePushLockShared(&Tracker->ConnectionListLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    count = 0;
    for (entry = Tracker->ConnectionList.Flink;
         entry != &Tracker->ConnectionList && count < capacity;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);
        CtAddRef(connection);
        snapshot[count++] = connection;
    }

    ExReleasePushLockShared(&Tracker->ConnectionListLock);

    //
    // Invoke callbacks outside all locks
    //
    for (i = 0; i < count; i++) {
        BOOLEAN continueEnum = Callback(snapshot[i], Context);
        CtRelease(snapshot[i]);
        if (!continueEnum) {
            //
            // Release remaining references
            //
            for (i = i + 1; i < count; i++) {
                CtRelease(snapshot[i]);
            }
            break;
        }
    }

    ExFreePoolWithTag(snapshot, CT_POOL_TAG_SNAP);

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
{
    if (Connection != NULL) {
        LONG newRef = InterlockedIncrement(&Connection->RefCount);
        NT_ASSERT(newRef > 1);  // Must not addref a zero-ref object
    }
}

_Use_decl_annotations_
VOID
CtRelease(
    _In_ PCT_CONNECTION Connection
    )
{
    LONG newRef;
    PCT_TRACKER_INTERNAL tracker;

    if (Connection == NULL) {
        return;
    }

    newRef = InterlockedDecrement(&Connection->RefCount);
    NT_ASSERT(newRef >= 0);

    if (newRef == 0) {
        //
        // Last reference dropped — free the connection.
        // The connection MUST have been removed from all lists before
        // the last reference is released (CtFlag_RemovedFromLists set).
        //
        NT_ASSERT(Connection->Flags & CtFlag_RemovedFromLists);
        NT_ASSERT(Connection->OwnerTracker != NULL);

        tracker = CONTAINING_RECORD(Connection->OwnerTracker, CT_TRACKER_INTERNAL, Public);
        CtpFreeConnection(tracker, Connection);
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
{
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
{
    ULONG hash = 0;
    SIZE_T addrSize = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);
    PUCHAR localBytes = (PUCHAR)LocalAddress;
    PUCHAR remoteBytes = (PUCHAR)RemoteAddress;
    SIZE_T i;

    // FNV-1a
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
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    return (ULONG)((pid >> 2) % CT_PROCESS_HASH_BUCKET_COUNT);
}

static PCT_PROCESS_CONTEXT
CtpGetOrCreateProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
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

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, HashListEntry);
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
    context->RefCount = 2; // One for hash table, one for caller

    //
    // Get process object reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &context->Process);
    if (!NT_SUCCESS(status)) {
        context->Process = NULL;
    }

    //
    // Initialize connection list and spin lock
    //
    InitializeListHead(&context->ConnectionList);
    KeInitializeSpinLock(&context->ConnectionLock);

    //
    // Resolve process info
    //
    CtpResolveProcessInfo(ProcessId, &context->ProcessName, NULL);

    //
    // Insert into hash and global list.
    // Acquire ProcessListLock first, then ProcessHash.Lock (lock ordering).
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ProcessListLock);
    ExAcquirePushLockExclusive(&Tracker->ProcessHash.Lock);

    //
    // Double-check: another thread may have created it concurrently
    //
    for (entry = Tracker->ProcessHash.Buckets[bucket].Flink;
         entry != &Tracker->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PCT_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, CT_PROCESS_CONTEXT, HashListEntry);
        if (ctx->ProcessId == ProcessId) {
            //
            // Race lost — free our new one, use existing
            //
            ExReleasePushLockExclusive(&Tracker->ProcessHash.Lock);
            ExReleasePushLockExclusive(&Tracker->Public.ProcessListLock);

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
    // Insert new context — separate ListEntry for hash and global list
    //
    InsertTailList(&Tracker->ProcessHash.Buckets[bucket], &context->HashListEntry);
    InsertTailList(&Tracker->Public.ProcessList, &context->GlobalListEntry);
    InterlockedIncrement(&Tracker->Public.ProcessCount);

    ExReleasePushLockExclusive(&Tracker->ProcessHash.Lock);
    ExReleasePushLockExclusive(&Tracker->Public.ProcessListLock);

    return context;
}

static VOID
CtpReleaseProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_PROCESS_CONTEXT Context
    )
{
    LONG newRef;

    if (Context == NULL) {
        return;
    }

    newRef = InterlockedDecrement(&Context->RefCount);
    NT_ASSERT(newRef >= 0);

    if (newRef == 0) {
        //
        // Last reference gone — remove from lists and free.
        // This should only happen during cleanup when the context
        // has already been removed from hash/global lists.
        //
        CtpFreeProcessContext(Tracker, Context);
    }
}

static VOID
CtpFreeProcessContext(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_PROCESS_CONTEXT Context
    )
{
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
        Context->Process = NULL;
    }

    if (Context->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Context->ProcessName.Buffer, CT_POOL_TAG_PROC);
        Context->ProcessName.Buffer = NULL;
    }

    if (Tracker->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Tracker->ProcessContextLookaside, Context);
    } else {
        ExFreePoolWithTag(Context, CT_POOL_TAG_PROC);
    }
}

static VOID
CtpResolveProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ProcessName,
    _Out_opt_ PUNICODE_STRING ProcessPath
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUCHAR imageFileName;

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
    // Use PsGetProcessImageFileName — safe, documented, returns a
    // pointer to the EPROCESS internal 15-char ANSI name. We convert
    // to UNICODE_STRING. This avoids SeLocateProcessImageName which
    // has ambiguous ownership semantics across Windows versions.
    //
    imageFileName = PsGetProcessImageFileName(process);
    if (imageFileName != NULL) {
        ANSI_STRING ansiName;
        UNICODE_STRING unicodeName;

        RtlInitAnsiString(&ansiName, (PCSZ)imageFileName);

        status = RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, TRUE);
        if (NT_SUCCESS(status)) {
            //
            // Allocate our own copy with our pool tag
            //
            ProcessName->MaximumLength = unicodeName.Length + sizeof(WCHAR);
            ProcessName->Buffer = (PWCH)ExAllocatePoolZero(
                NonPagedPoolNx,
                ProcessName->MaximumLength,
                CT_POOL_TAG_PROC
            );

            if (ProcessName->Buffer != NULL) {
                RtlCopyMemory(ProcessName->Buffer, unicodeName.Buffer, unicodeName.Length);
                ProcessName->Length = unicodeName.Length;
            } else {
                ProcessName->MaximumLength = 0;
            }

            RtlFreeUnicodeString(&unicodeName);
        }
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
{
    CT_CALLBACK_ENTRY callbackSnapshot[CT_MAX_CALLBACKS];
    ULONG i;
    ULONG count = 0;

    if (Tracker->CallbackCount == 0) {
        return;
    }

    //
    // Snapshot callbacks under the lock, then invoke outside.
    // This prevents deadlock if a callback tries to unregister
    // itself or do other tracker operations (though callbacks
    // MUST NOT call back into Ct* APIs per contract).
    //
    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < CT_MAX_CALLBACKS; i++) {
        if (Tracker->Callbacks[i].InUse && Tracker->Callbacks[i].Callback != NULL) {
            callbackSnapshot[count] = Tracker->Callbacks[i];
            count++;
        }
    }

    ExReleasePushLockShared(&Tracker->CallbackLock);

    //
    // Invoke callbacks outside all locks
    //
    for (i = 0; i < count; i++) {
        callbackSnapshot[i].Callback(
            Connection,
            OldState,
            NewState,
            callbackSnapshot[i].Context
        );
    }
}

static VOID
CtpRemoveConnectionFromLists(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    )
{
    ULONG flowBucket;
    PLIST_ENTRY entry;
    PCT_FLOW_HASH_ENTRY flowEntry = NULL;
    KIRQL oldIrql;

    //
    // Atomically check if already removed
    //
    if (InterlockedOr(&Connection->Flags, CtFlag_RemovedFromLists) & CtFlag_RemovedFromLists) {
        return;  // Already removed by another thread
    }

    //
    // Remove from global list (lock order #1)
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ConnectionListLock);
    RemoveEntryList(&Connection->GlobalListEntry);
    InitializeListHead(&Connection->GlobalListEntry);
    InterlockedDecrement(&Tracker->Public.ConnectionCount);
    ExReleasePushLockExclusive(&Tracker->Public.ConnectionListLock);

    //
    // Remove from connection hash (lock order #2)
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ConnectionHash.Lock);
    RemoveEntryList(&Connection->HashListEntry);
    InitializeListHead(&Connection->HashListEntry);
    ExReleasePushLockExclusive(&Tracker->Public.ConnectionHash.Lock);

    //
    // Remove from flow hash (lock order #3)
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
    // Remove from process context (lock order #6)
    //
    if (Connection->ProcessContextRef != NULL) {
        PCT_PROCESS_CONTEXT processCtx = Connection->ProcessContextRef;

        KeAcquireSpinLock(&processCtx->ConnectionLock, &oldIrql);
        RemoveEntryList(&Connection->ProcessListEntry);
        InitializeListHead(&Connection->ProcessListEntry);
        InterlockedDecrement(&processCtx->ConnectionCount);

        {
            CT_CONNECTION_STATE state = (CT_CONNECTION_STATE)Connection->State;
            if (state == CtState_Connected ||
                state == CtState_Established ||
                state == CtState_Connecting ||
                state == CtState_New) {
                InterlockedDecrement(&processCtx->ActiveConnectionCount);
            }
        }

        KeReleaseSpinLock(&processCtx->ConnectionLock, oldIrql);

        //
        // Release the process context reference held by this connection
        //
        CtpReleaseProcessContext(Tracker, processCtx);
        Connection->ProcessContextRef = NULL;
    }

    //
    // Release the "in lists" reference. If this was the last reference,
    // CtRelease will call CtpFreeConnection.
    //
    CtRelease(Connection);
}

static VOID
CtpFreeConnection(
    _In_ PCT_TRACKER_INTERNAL Tracker,
    _In_ PCT_CONNECTION Connection
    )
{
    if (Connection->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Connection->ProcessName.Buffer, CT_POOL_TAG_CONN);
        Connection->ProcessName.Buffer = NULL;
    }

    if (Connection->ProcessPath.Buffer != NULL) {
        ExFreePoolWithTag(Connection->ProcessPath.Buffer, CT_POOL_TAG_CONN);
        Connection->ProcessPath.Buffer = NULL;
    }

    if (Connection->TlsInfo != NULL) {
        ExFreePoolWithTag(Connection->TlsInfo, CT_POOL_TAG_CONN);
        Connection->TlsInfo = NULL;
    }

    if (Tracker->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Tracker->ConnectionLookaside, Connection);
    } else {
        ExFreePoolWithTag(Connection, CT_POOL_TAG_CONN);
    }
}

// ============================================================================
// CLEANUP TIMER AND WORK ITEM
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CtpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PCT_TRACKER_INTERNAL tracker = (PCT_TRACKER_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (tracker == NULL || tracker->ShuttingDown) {
        return;
    }

    //
    // The DPC runs at DISPATCH_LEVEL — we MUST NOT touch push locks here.
    // Instead, queue a work item that runs at PASSIVE_LEVEL.
    //
    if (InterlockedCompareExchange(&tracker->CleanupWorkItemPending, 1, 0) == 0) {
        ExQueueWorkItem(&tracker->CleanupWorkQueueItem, DelayedWorkQueue);
    }
}

static VOID
CtpCleanupWorkItemRoutine(
    _In_ PVOID Parameter
    )
{
    PCT_TRACKER_INTERNAL tracker = (PCT_TRACKER_INTERNAL)Parameter;

    PAGED_CODE();

    if (tracker == NULL || tracker->ShuttingDown) {
        if (tracker != NULL) {
            InterlockedExchange(&tracker->CleanupWorkItemPending, 0);
        }
        return;
    }

    CtpCleanupStaleConnections(tracker);

    //
    // Re-initialize work item for next use.
    // ExQueueWorkItem requires the item to be re-initialized after completion.
    //
    ExInitializeWorkItem(
        &tracker->CleanupWorkQueueItem,
        CtpCleanupWorkItemRoutine,
        tracker
    );

    InterlockedExchange(&tracker->CleanupWorkItemPending, 0);
}

static VOID
CtpCleanupStaleConnections(
    _In_ PCT_TRACKER_INTERNAL Tracker
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PCT_CONNECTION connection;
    PCT_CONNECTION* staleList = NULL;
    ULONG staleCount = 0;
    ULONG staleCapacity = 0;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeoutInterval;
    ULONG i;

    PAGED_CODE();

    KeQuerySystemTime(&currentTime);
    timeoutInterval.QuadPart = (LONGLONG)Tracker->Public.Config.ConnectionTimeoutMs * 10000;

    //
    // First pass: under shared lock, count stale candidates and update idle times
    //
    ExAcquirePushLockShared(&Tracker->Public.ConnectionListLock);

    for (entry = Tracker->Public.ConnectionList.Flink;
         entry != &Tracker->Public.ConnectionList;
         entry = entry->Flink) {

        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);
        CT_CONNECTION_STATE state = (CT_CONNECTION_STATE)connection->State;

        if (state == CtState_Closed || state == CtState_TimedOut ||
            state == CtState_Blocked || state == CtState_Error) {
            staleCapacity++;
        } else {
            //
            // Update idle time for active connections
            //
            LONG64 lastPacket = InterlockedCompareExchange64(
                &connection->Stats.LastPacketTime, 0, 0);
            LARGE_INTEGER idleTime;
            idleTime.QuadPart = currentTime.QuadPart - lastPacket;

            if (idleTime.QuadPart > timeoutInterval.QuadPart) {
                InterlockedExchange(
                    &connection->Stats.IdleTimeMs,
                    (LONG)(idleTime.QuadPart / 10000));

                //
                // Transition idle connections to TimedOut
                //
                InterlockedCompareExchange(&connection->State,
                    (LONG)CtState_TimedOut,
                    (LONG)state);
                staleCapacity++;
            }
        }
    }

    ExReleasePushLockShared(&Tracker->Public.ConnectionListLock);

    if (staleCapacity == 0) {
        return;
    }

    //
    // Allocate array for stale connection pointers
    //
    staleList = (PCT_CONNECTION*)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PCT_CONNECTION) * staleCapacity,
        CT_POOL_TAG_SNAP
    );

    if (staleList == NULL) {
        return;  // Best-effort cleanup; will retry next cycle
    }

    //
    // Second pass: under exclusive lock, collect stale connections
    // with refcount == 1 (only the lists reference remains).
    //
    ExAcquirePushLockExclusive(&Tracker->Public.ConnectionListLock);

    for (entry = Tracker->Public.ConnectionList.Flink;
         entry != &Tracker->Public.ConnectionList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        connection = CONTAINING_RECORD(entry, CT_CONNECTION, GlobalListEntry);
        CT_CONNECTION_STATE state = (CT_CONNECTION_STATE)connection->State;

        if ((state == CtState_Closed || state == CtState_TimedOut ||
             state == CtState_Blocked || state == CtState_Error) &&
            connection->RefCount == 1 &&
            staleCount < staleCapacity) {

            //
            // Add ref to prevent free while we still hold a pointer
            //
            CtAddRef(connection);
            staleList[staleCount++] = connection;
        }
    }

    ExReleasePushLockExclusive(&Tracker->Public.ConnectionListLock);

    //
    // Remove and release collected connections outside the lock.
    // CtpRemoveConnectionFromLists handles idempotent removal and
    // releases the "in-lists" reference. Our extra ref keeps the
    // object alive until we release it.
    //
    for (i = 0; i < staleCount; i++) {
        CtpRemoveConnectionFromLists(Tracker, staleList[i]);
        CtRelease(staleList[i]);  // Release our temporary ref
    }

    ExFreePoolWithTag(staleList, CT_POOL_TAG_SNAP);
}
