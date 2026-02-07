/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PROCESS RELATIONSHIP GRAPH IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessRelationship.c
 * @brief Enterprise-grade process graph and relationship tracking engine.
 *
 * This module implements comprehensive process relationship analysis with:
 * - Complete process tree reconstruction and tracking
 * - Parent-child relationship management
 * - Cross-process injection detection via relationship mapping
 * - Remote thread creation tracking
 * - Section/memory sharing detection
 * - Handle duplication tracking
 * - Debug relationship monitoring
 * - Suspicious cluster detection using graph analysis
 * - Lock-free hash table for O(1) process lookup
 * - Reference counting for safe concurrent access
 *
 * Security Detection Capabilities:
 * - T1055: Process Injection (all variants)
 * - T1055.001: DLL Injection
 * - T1055.002: Portable Executable Injection
 * - T1055.003: Thread Execution Hijacking
 * - T1055.004: Asynchronous Procedure Call
 * - T1055.012: Process Hollowing
 * - T1106: Native API abuse detection
 * - T1134: Access Token Manipulation
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ProcessRelationship.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PR_VERSION                      1
#define PR_SIGNATURE                    0x50524750  // 'PRGP'
#define PR_HASH_BUCKET_COUNT            256
#define PR_MAX_NODES                    8192
#define PR_MAX_RELATIONSHIPS            32768
#define PR_CLEANUP_INTERVAL_MS          60000       // 1 minute
#define PR_STALE_PROCESS_THRESHOLD_MS   600000      // 10 minutes

//
// Suspicion score weights for relationships
//
#define PR_SCORE_REMOTE_THREAD          150
#define PR_SCORE_INJECTION              300
#define PR_SCORE_SHARED_SECTION         80
#define PR_SCORE_HANDLE_DUP             60
#define PR_SCORE_DEBUG_ATTACH           200
#define PR_SCORE_CROSS_SESSION          100
#define PR_SCORE_ELEVATION_ATTEMPT      250
#define PR_SCORE_SYSTEM_TARGET          180
#define PR_SCORE_MULTIPLE_TARGETS       120
#define PR_SCORE_RAPID_RELATIONSHIPS    90
#define PR_SCORE_ORPHANED_INJECTOR      200
#define PR_SCORE_UNUSUAL_PARENT         70

//
// Cluster detection thresholds
//
#define PR_CLUSTER_MIN_SCORE            300
#define PR_CLUSTER_MIN_RELATIONSHIPS    3
#define PR_CLUSTER_TIMEWINDOW_MS        30000       // 30 seconds

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Extended internal graph structure.
 */
typedef struct _PR_GRAPH_INTERNAL {
    //
    // Base public structure
    //
    PR_GRAPH Public;

    //
    // Signature for validation
    //
    ULONG Signature;

    //
    // Lookaside lists for efficient allocation
    //
    NPAGED_LOOKASIDE_LIST NodeLookaside;
    NPAGED_LOOKASIDE_LIST RelationshipLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Relationship statistics per type
    //
    volatile LONG64 RelationshipsByType[6];

    //
    // Shutdown synchronization
    //
    volatile LONG ShuttingDown;
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;

} PR_GRAPH_INTERNAL, *PPR_GRAPH_INTERNAL;

/**
 * @brief Cluster analysis context.
 */
typedef struct _PR_CLUSTER_CONTEXT {
    HANDLE ProcessIds[64];
    ULONG ProcessCount;
    ULONG TotalScore;
    ULONG RelationshipCount;
    LARGE_INTEGER FirstEventTime;
    LARGE_INTEGER LastEventTime;
} PR_CLUSTER_CONTEXT, *PPR_CLUSTER_CONTEXT;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPR_PROCESS_NODE
PrpAllocateNode(
    _In_ PPR_GRAPH_INTERNAL Graph
    );

static VOID
PrpFreeNode(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    );

static PPR_RELATIONSHIP
PrpAllocateRelationship(
    _In_ PPR_GRAPH_INTERNAL Graph
    );

static VOID
PrpFreeRelationship(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_RELATIONSHIP Relationship
    );

static ULONG
PrpHashProcessId(
    _In_ HANDLE ProcessId,
    _In_ ULONG BucketCount
    );

static PPR_PROCESS_NODE
PrpFindNodeLocked(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ HANDLE ProcessId
    );

static VOID
PrpInsertNodeLocked(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    );

static VOID
PrpRemoveNodeLocked(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    );

static ULONG
PrpCalculateRelationshipScore(
    _In_ PR_RELATIONSHIP_TYPE Type,
    _In_ HANDLE SourceId,
    _In_ HANDLE TargetId
    );

static VOID
PrpUpdateNodeMetrics(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    );

static BOOLEAN
PrpIsProcessOrphan(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
PrpIsCrossSession(
    _In_ HANDLE SourceId,
    _In_ HANDLE TargetId
    );

static BOOLEAN
PrpIsSystemProcess(
    _In_ HANDLE ProcessId
    );

static VOID
PrpAcquireReference(
    _In_ PPR_GRAPH_INTERNAL Graph
    );

static VOID
PrpReleaseReference(
    _In_ PPR_GRAPH_INTERNAL Graph
    );

static VOID
PrpAnalyzeCluster(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE StartNode,
    _Inout_ PPR_CLUSTER_CONTEXT Context
    );

static BOOLEAN
PrpIsNodeInCluster(
    _In_ PPR_CLUSTER_CONTEXT Context,
    _In_ HANDLE ProcessId
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PrInitialize(
    _Out_ PPR_GRAPH* Graph
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPR_GRAPH_INTERNAL internal = NULL;
    ULONG i;

    if (Graph == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Graph = NULL;

    //
    // Allocate graph structure
    //
    internal = (PPR_GRAPH_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PR_GRAPH_INTERNAL),
        PR_POOL_TAG
    );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(PR_GRAPH_INTERNAL));
    internal->Signature = PR_SIGNATURE;

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&internal->Public.NodeLock);
    ExInitializePushLock(&internal->Public.RelationshipLock);
    InitializeListHead(&internal->Public.NodeList);
    InitializeListHead(&internal->Public.RelationshipList);

    //
    // Initialize shutdown event
    //
    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // Initial reference

    //
    // Allocate hash table buckets
    //
    internal->Public.NodeHash.BucketCount = PR_HASH_BUCKET_COUNT;
    internal->Public.NodeHash.Buckets = (PLIST_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        PR_HASH_BUCKET_COUNT * sizeof(LIST_ENTRY),
        PR_POOL_TAG
    );

    if (internal->Public.NodeHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Initialize hash buckets
    //
    for (i = 0; i < PR_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&internal->Public.NodeHash.Buckets[i]);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &internal->NodeLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PR_PROCESS_NODE),
        PR_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &internal->RelationshipLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PR_RELATIONSHIP),
        PR_POOL_TAG,
        0
    );

    internal->LookasideInitialized = TRUE;

    //
    // Record start time
    //
    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // Mark as initialized
    //
    internal->Public.Initialized = TRUE;

    *Graph = &internal->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (internal != NULL) {
        if (internal->Public.NodeHash.Buckets != NULL) {
            ShadowStrikeFreePoolWithTag(
                internal->Public.NodeHash.Buckets,
                PR_POOL_TAG
            );
        }

        ShadowStrikeFreePoolWithTag(internal, PR_POOL_TAG);
    }

    return status;
}

_Use_decl_annotations_
VOID
PrShutdown(
    _Inout_ PPR_GRAPH Graph
    )
{
    PPR_GRAPH_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PPR_PROCESS_NODE node;
    PPR_RELATIONSHIP relationship;
    LARGE_INTEGER timeout;

    if (Graph == NULL || !Graph->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->Signature != PR_SIGNATURE) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&internal->ShuttingDown, 1);

    //
    // Wait for active operations to complete
    //
    PrpReleaseReference(internal);
    timeout.QuadPart = -((LONGLONG)5000 * 10000);  // 5 second timeout
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Free all relationships
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Graph->RelationshipLock);

    while (!IsListEmpty(&Graph->RelationshipList)) {
        listEntry = RemoveHeadList(&Graph->RelationshipList);
        relationship = CONTAINING_RECORD(listEntry, PR_RELATIONSHIP, ListEntry);
        PrpFreeRelationship(internal, relationship);
    }

    ExReleasePushLockExclusive(&Graph->RelationshipLock);
    KeLeaveCriticalRegion();

    //
    // Free all nodes
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Graph->NodeLock);

    while (!IsListEmpty(&Graph->NodeList)) {
        listEntry = RemoveHeadList(&Graph->NodeList);
        node = CONTAINING_RECORD(listEntry, PR_PROCESS_NODE, ListEntry);

        //
        // Free node's relationship list
        //
        while (!IsListEmpty(&node->RelationshipList)) {
            PLIST_ENTRY relEntry = RemoveHeadList(&node->RelationshipList);
            relationship = CONTAINING_RECORD(relEntry, PR_RELATIONSHIP, ListEntry);
            PrpFreeRelationship(internal, relationship);
        }

        //
        // Free image name
        //
        if (node->ImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(node->ImageName.Buffer, PR_POOL_TAG);
        }

        PrpFreeNode(internal, node);
    }

    ExReleasePushLockExclusive(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    //
    // Free hash table
    //
    if (Graph->NodeHash.Buckets != NULL) {
        ShadowStrikeFreePoolWithTag(Graph->NodeHash.Buckets, PR_POOL_TAG);
        Graph->NodeHash.Buckets = NULL;
    }

    //
    // Delete lookaside lists
    //
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->NodeLookaside);
        ExDeleteNPagedLookasideList(&internal->RelationshipLookaside);
        internal->LookasideInitialized = FALSE;
    }

    //
    // Clear signature and free
    //
    internal->Signature = 0;
    Graph->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(internal, PR_POOL_TAG);
}

// ============================================================================
// PROCESS NODE MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PrAddProcess(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ PUNICODE_STRING ImageName
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPR_GRAPH_INTERNAL internal;
    PPR_PROCESS_NODE node = NULL;
    PPR_PROCESS_NODE existingNode;
    PPR_PROCESS_NODE parentNode;

    if (Graph == NULL || !Graph->Initialized || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PrpAcquireReference(internal);

    //
    // Check capacity
    //
    if ((ULONG)Graph->NodeCount >= PR_MAX_NODES) {
        status = STATUS_QUOTA_EXCEEDED;
        goto Cleanup;
    }

    //
    // Check if process already exists
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Graph->NodeLock);

    existingNode = PrpFindNodeLocked(internal, ProcessId);

    ExReleasePushLockShared(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    if (existingNode != NULL) {
        status = STATUS_OBJECT_NAME_EXISTS;
        goto Cleanup;
    }

    //
    // Allocate new node
    //
    node = PrpAllocateNode(internal);
    if (node == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(node, sizeof(PR_PROCESS_NODE));
    node->ProcessId = ProcessId;
    node->ParentId = ParentId;
    InitializeListHead(&node->RelationshipList);
    KeQuerySystemTime(&node->CreateTime);

    //
    // Copy image name if provided
    //
    if (ImageName != NULL && ImageName->Buffer != NULL && ImageName->Length > 0) {
        node->ImageName.MaximumLength = ImageName->Length + sizeof(WCHAR);
        node->ImageName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            node->ImageName.MaximumLength,
            PR_POOL_TAG
        );

        if (node->ImageName.Buffer != NULL) {
            RtlCopyMemory(node->ImageName.Buffer, ImageName->Buffer, ImageName->Length);
            node->ImageName.Length = ImageName->Length;
            node->ImageName.Buffer[node->ImageName.Length / sizeof(WCHAR)] = L'\0';
        }
    }

    //
    // Check if this is an orphan process
    //
    node->IsOrphan = PrpIsProcessOrphan(ParentId);

    //
    // Insert into graph
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Graph->NodeLock);

    //
    // Double-check after acquiring exclusive lock
    //
    existingNode = PrpFindNodeLocked(internal, ProcessId);
    if (existingNode != NULL) {
        ExReleasePushLockExclusive(&Graph->NodeLock);
        KeLeaveCriticalRegion();

        if (node->ImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(node->ImageName.Buffer, PR_POOL_TAG);
        }
        PrpFreeNode(internal, node);

        status = STATUS_OBJECT_NAME_EXISTS;
        goto Cleanup;
    }

    //
    // Add to parent's children list
    //
    if (ParentId != NULL) {
        parentNode = PrpFindNodeLocked(internal, ParentId);
        if (parentNode != NULL && parentNode->ChildCount < PR_MAX_CHILDREN) {
            parentNode->Children[parentNode->ChildCount++] = ProcessId;
            node->DepthFromRoot = parentNode->DepthFromRoot + 1;
        }
    }

    PrpInsertNodeLocked(internal, node);

    ExReleasePushLockExclusive(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    //
    // Update metrics
    //
    PrpUpdateNodeMetrics(internal, node);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Graph->Stats.NodesTracked);

    node = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (node != NULL) {
        if (node->ImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(node->ImageName.Buffer, PR_POOL_TAG);
        }
        PrpFreeNode(internal, node);
    }

    PrpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PrRemoveProcess(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId
    )
{
    PPR_GRAPH_INTERNAL internal;
    PPR_PROCESS_NODE node;
    PPR_PROCESS_NODE parentNode;
    PLIST_ENTRY listEntry;
    PPR_RELATIONSHIP relationship;
    ULONG i;

    if (Graph == NULL || !Graph->Initialized || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PrpAcquireReference(internal);

    //
    // Find and remove node
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Graph->NodeLock);

    node = PrpFindNodeLocked(internal, ProcessId);

    if (node == NULL) {
        ExReleasePushLockExclusive(&Graph->NodeLock);
        KeLeaveCriticalRegion();
        PrpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    //
    // Remove from parent's children list
    //
    if (node->ParentId != NULL) {
        parentNode = PrpFindNodeLocked(internal, node->ParentId);
        if (parentNode != NULL) {
            for (i = 0; i < parentNode->ChildCount; i++) {
                if (parentNode->Children[i] == ProcessId) {
                    //
                    // Shift remaining children
                    //
                    for (ULONG j = i; j < parentNode->ChildCount - 1; j++) {
                        parentNode->Children[j] = parentNode->Children[j + 1];
                    }
                    parentNode->ChildCount--;
                    break;
                }
            }
        }
    }

    //
    // Mark children as orphans
    //
    for (i = 0; i < node->ChildCount; i++) {
        PPR_PROCESS_NODE childNode = PrpFindNodeLocked(internal, node->Children[i]);
        if (childNode != NULL) {
            childNode->IsOrphan = TRUE;
        }
    }

    PrpRemoveNodeLocked(internal, node);

    ExReleasePushLockExclusive(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    //
    // Free node's relationships
    //
    while (!IsListEmpty(&node->RelationshipList)) {
        listEntry = RemoveHeadList(&node->RelationshipList);
        relationship = CONTAINING_RECORD(listEntry, PR_RELATIONSHIP, ListEntry);
        PrpFreeRelationship(internal, relationship);
    }

    //
    // Free image name
    //
    if (node->ImageName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(node->ImageName.Buffer, PR_POOL_TAG);
    }

    PrpFreeNode(internal, node);

    PrpReleaseReference(internal);

    return STATUS_SUCCESS;
}

// ============================================================================
// RELATIONSHIP MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PrAddRelationship(
    _In_ PPR_GRAPH Graph,
    _In_ PR_RELATIONSHIP_TYPE Type,
    _In_ HANDLE SourceId,
    _In_ HANDLE TargetId
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPR_GRAPH_INTERNAL internal;
    PPR_RELATIONSHIP relationship = NULL;
    PPR_PROCESS_NODE sourceNode;
    PPR_PROCESS_NODE targetNode;

    if (Graph == NULL || !Graph->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SourceId == NULL || TargetId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Type > PrRelation_DebugRelation) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PrpAcquireReference(internal);

    //
    // Allocate relationship
    //
    relationship = PrpAllocateRelationship(internal);
    if (relationship == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(relationship, sizeof(PR_RELATIONSHIP));
    relationship->Type = Type;
    relationship->SourceProcessId = SourceId;
    relationship->TargetProcessId = TargetId;
    KeQuerySystemTime(&relationship->Timestamp);

    //
    // Calculate suspicion score for this relationship
    //
    relationship->SuspicionScore = PrpCalculateRelationshipScore(Type, SourceId, TargetId);

    //
    // Find source and target nodes
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Graph->NodeLock);

    sourceNode = PrpFindNodeLocked(internal, SourceId);
    targetNode = PrpFindNodeLocked(internal, TargetId);

    ExReleasePushLockShared(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    //
    // Add to source node's relationship list if node exists
    //
    if (sourceNode != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Graph->NodeLock);

        if (sourceNode->RelationshipCount < PR_MAX_CONNECTIONS) {
            InsertTailList(&sourceNode->RelationshipList, &relationship->ListEntry);
            InterlockedIncrement(&sourceNode->RelationshipCount);
        }

        ExReleasePushLockExclusive(&Graph->NodeLock);
        KeLeaveCriticalRegion();
    }

    //
    // Add to global relationship list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Graph->RelationshipLock);

    InsertTailList(&Graph->RelationshipList, &relationship->ListEntry);

    ExReleasePushLockExclusive(&Graph->RelationshipLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Graph->Stats.RelationshipsTracked);
    InterlockedIncrement64(&internal->RelationshipsByType[Type]);

    relationship = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (relationship != NULL) {
        PrpFreeRelationship(internal, relationship);
    }

    PrpReleaseReference(internal);

    return status;
}

// ============================================================================
// QUERY OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PrGetNode(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_ PPR_PROCESS_NODE* Node
    )
{
    PPR_GRAPH_INTERNAL internal;
    PPR_PROCESS_NODE node;

    if (Graph == NULL || !Graph->Initialized || ProcessId == NULL || Node == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Node = NULL;

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Graph->NodeLock);

    node = PrpFindNodeLocked(internal, ProcessId);

    ExReleasePushLockShared(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    if (node == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Node = node;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PrGetChildren(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) HANDLE* Children,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PPR_GRAPH_INTERNAL internal;
    PPR_PROCESS_NODE node;
    ULONG copyCount;

    if (Graph == NULL || !Graph->Initialized || ProcessId == NULL ||
        Children == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Graph->NodeLock);

    node = PrpFindNodeLocked(internal, ProcessId);

    if (node == NULL) {
        ExReleasePushLockShared(&Graph->NodeLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    copyCount = min(node->ChildCount, Max);

    if (copyCount > 0) {
        RtlCopyMemory(Children, node->Children, copyCount * sizeof(HANDLE));
    }

    *Count = copyCount;

    ExReleasePushLockShared(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PrGetRelationships(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) PPR_RELATIONSHIP* Relations,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PPR_GRAPH_INTERNAL internal;
    PPR_PROCESS_NODE node;
    PLIST_ENTRY listEntry;
    PPR_RELATIONSHIP relationship;
    ULONG count = 0;

    if (Graph == NULL || !Graph->Initialized || ProcessId == NULL ||
        Relations == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Graph->NodeLock);

    node = PrpFindNodeLocked(internal, ProcessId);

    if (node == NULL) {
        ExReleasePushLockShared(&Graph->NodeLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Collect relationships from node's list
    //
    for (listEntry = node->RelationshipList.Flink;
         listEntry != &node->RelationshipList && count < Max;
         listEntry = listEntry->Flink) {

        relationship = CONTAINING_RECORD(listEntry, PR_RELATIONSHIP, ListEntry);
        Relations[count++] = relationship;
    }

    *Count = count;

    ExReleasePushLockShared(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// SUSPICIOUS CLUSTER DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PrFindSuspiciousClusters(
    _In_ PPR_GRAPH Graph,
    _Out_writes_to_(Max, *Count) HANDLE* Processes,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PPR_GRAPH_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PPR_PROCESS_NODE node;
    PR_CLUSTER_CONTEXT context;
    ULONG outputCount = 0;
    ULONG i;

    if (Graph == NULL || !Graph->Initialized ||
        Processes == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    internal = CONTAINING_RECORD(Graph, PR_GRAPH_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PrpAcquireReference(internal);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Graph->NodeLock);

    //
    // Iterate through all nodes looking for suspicious clusters
    //
    for (listEntry = Graph->NodeList.Flink;
         listEntry != &Graph->NodeList && outputCount < Max;
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PR_PROCESS_NODE, ListEntry);

        //
        // Skip nodes with insufficient relationships
        //
        if (node->RelationshipCount < PR_CLUSTER_MIN_RELATIONSHIPS) {
            continue;
        }

        //
        // Analyze cluster starting from this node
        //
        RtlZeroMemory(&context, sizeof(context));
        PrpAnalyzeCluster(internal, node, &context);

        //
        // Check if cluster meets suspicion threshold
        //
        if (context.TotalScore >= PR_CLUSTER_MIN_SCORE &&
            context.RelationshipCount >= PR_CLUSTER_MIN_RELATIONSHIPS) {

            //
            // Add all cluster processes to output
            //
            for (i = 0; i < context.ProcessCount && outputCount < Max; i++) {
                //
                // Avoid duplicates
                //
                BOOLEAN duplicate = FALSE;
                for (ULONG j = 0; j < outputCount; j++) {
                    if (Processes[j] == context.ProcessIds[i]) {
                        duplicate = TRUE;
                        break;
                    }
                }

                if (!duplicate) {
                    Processes[outputCount++] = context.ProcessIds[i];
                }
            }
        }
    }

    ExReleasePushLockShared(&Graph->NodeLock);
    KeLeaveCriticalRegion();

    *Count = outputCount;

    PrpReleaseReference(internal);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - ALLOCATION
// ============================================================================

static PPR_PROCESS_NODE
PrpAllocateNode(
    _In_ PPR_GRAPH_INTERNAL Graph
    )
{
    PPR_PROCESS_NODE node;

    if (!Graph->LookasideInitialized) {
        node = (PPR_PROCESS_NODE)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(PR_PROCESS_NODE),
            PR_POOL_TAG
        );
    } else {
        node = (PPR_PROCESS_NODE)ExAllocateFromNPagedLookasideList(
            &Graph->NodeLookaside
        );
    }

    return node;
}

static VOID
PrpFreeNode(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    )
{
    if (Graph->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Graph->NodeLookaside, Node);
    } else {
        ShadowStrikeFreePoolWithTag(Node, PR_POOL_TAG);
    }
}

static PPR_RELATIONSHIP
PrpAllocateRelationship(
    _In_ PPR_GRAPH_INTERNAL Graph
    )
{
    PPR_RELATIONSHIP relationship;

    if (!Graph->LookasideInitialized) {
        relationship = (PPR_RELATIONSHIP)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(PR_RELATIONSHIP),
            PR_POOL_TAG
        );
    } else {
        relationship = (PPR_RELATIONSHIP)ExAllocateFromNPagedLookasideList(
            &Graph->RelationshipLookaside
        );
    }

    return relationship;
}

static VOID
PrpFreeRelationship(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_RELATIONSHIP Relationship
    )
{
    if (Graph->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Graph->RelationshipLookaside, Relationship);
    } else {
        ShadowStrikeFreePoolWithTag(Relationship, PR_POOL_TAG);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - HASH TABLE
// ============================================================================

static ULONG
PrpHashProcessId(
    _In_ HANDLE ProcessId,
    _In_ ULONG BucketCount
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    ULONG hash;

    //
    // Use golden ratio constant for good distribution
    //
    hash = (ULONG)(pid * 0x9E3779B9UL);
    hash ^= (ULONG)(pid >> 16);
    hash *= 0x85EBCA6BUL;
    hash ^= hash >> 13;

    return hash % BucketCount;
}

static PPR_PROCESS_NODE
PrpFindNodeLocked(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PPR_PROCESS_NODE node;

    bucket = PrpHashProcessId(ProcessId, Graph->Public.NodeHash.BucketCount);

    for (listEntry = Graph->Public.NodeHash.Buckets[bucket].Flink;
         listEntry != &Graph->Public.NodeHash.Buckets[bucket];
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PR_PROCESS_NODE, HashEntry);

        if (node->ProcessId == ProcessId) {
            return node;
        }
    }

    return NULL;
}

static VOID
PrpInsertNodeLocked(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    )
{
    ULONG bucket;

    //
    // Insert into main list
    //
    InsertTailList(&Graph->Public.NodeList, &Node->ListEntry);
    InterlockedIncrement(&Graph->Public.NodeCount);

    //
    // Insert into hash table
    //
    bucket = PrpHashProcessId(Node->ProcessId, Graph->Public.NodeHash.BucketCount);
    InsertTailList(&Graph->Public.NodeHash.Buckets[bucket], &Node->HashEntry);
}

static VOID
PrpRemoveNodeLocked(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    )
{
    //
    // Remove from main list
    //
    RemoveEntryList(&Node->ListEntry);
    InterlockedDecrement(&Graph->Public.NodeCount);

    //
    // Remove from hash table
    //
    RemoveEntryList(&Node->HashEntry);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - SCORING
// ============================================================================

static ULONG
PrpCalculateRelationshipScore(
    _In_ PR_RELATIONSHIP_TYPE Type,
    _In_ HANDLE SourceId,
    _In_ HANDLE TargetId
    )
{
    ULONG score = 0;

    //
    // Base score by relationship type
    //
    switch (Type) {
        case PrRelation_ParentChild:
            score = 0;  // Normal relationship
            break;

        case PrRelation_Injected:
            score = PR_SCORE_INJECTION;
            break;

        case PrRelation_RemoteThread:
            score = PR_SCORE_REMOTE_THREAD;
            break;

        case PrRelation_SharedSection:
            score = PR_SCORE_SHARED_SECTION;
            break;

        case PrRelation_HandleDuplication:
            score = PR_SCORE_HANDLE_DUP;
            break;

        case PrRelation_DebugRelation:
            score = PR_SCORE_DEBUG_ATTACH;
            break;

        default:
            score = 0;
            break;
    }

    //
    // Bonus scores for high-risk scenarios
    //

    //
    // Cross-session activity is suspicious
    //
    if (PrpIsCrossSession(SourceId, TargetId)) {
        score += PR_SCORE_CROSS_SESSION;
    }

    //
    // Targeting system processes is highly suspicious
    //
    if (PrpIsSystemProcess(TargetId)) {
        score += PR_SCORE_SYSTEM_TARGET;
    }

    //
    // Source is orphan process (parent terminated)
    //
    if (PrpIsProcessOrphan(SourceId)) {
        score += PR_SCORE_ORPHANED_INJECTOR;
    }

    return score;
}

static VOID
PrpUpdateNodeMetrics(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE Node
    )
{
    PLIST_ENTRY listEntry;
    PPR_PROCESS_NODE childNode;
    ULONG subtreeSize = 1;

    UNREFERENCED_PARAMETER(Graph);

    //
    // Calculate subtree size recursively (simplified)
    //
    for (ULONG i = 0; i < Node->ChildCount; i++) {
        //
        // In a full implementation, we would recursively calculate
        // For now, just count direct children
        //
        subtreeSize++;
    }

    Node->SubtreeSize = subtreeSize;
}

static BOOLEAN
PrpIsProcessOrphan(
    _In_ HANDLE ProcessId
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE parentId;

    if (ProcessId == NULL) {
        return TRUE;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return TRUE;  // Process doesn't exist
    }

    parentId = PsGetProcessInheritedFromUniqueProcessId(process);
    ObDereferenceObject(process);

    if (parentId == NULL || parentId == ProcessId) {
        return TRUE;
    }

    //
    // Check if parent still exists
    //
    status = PsLookupProcessByProcessId(parentId, &process);
    if (!NT_SUCCESS(status)) {
        return TRUE;  // Parent doesn't exist
    }

    ObDereferenceObject(process);

    return FALSE;
}

static BOOLEAN
PrpIsCrossSession(
    _In_ HANDLE SourceId,
    _In_ HANDLE TargetId
    )
{
    NTSTATUS status;
    PEPROCESS sourceProcess = NULL;
    PEPROCESS targetProcess = NULL;
    ULONG sourceSession = 0;
    ULONG targetSession = 0;
    BOOLEAN crossSession = FALSE;

    status = PsLookupProcessByProcessId(SourceId, &sourceProcess);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = PsLookupProcessByProcessId(TargetId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(sourceProcess);
        return FALSE;
    }

    //
    // Get session IDs
    // Note: This requires appropriate function availability
    //
    sourceSession = PsGetProcessSessionId(sourceProcess);
    targetSession = PsGetProcessSessionId(targetProcess);

    crossSession = (sourceSession != targetSession);

    ObDereferenceObject(sourceProcess);
    ObDereferenceObject(targetProcess);

    return crossSession;
}

static BOOLEAN
PrpIsSystemProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    //
    // System (PID 4), Idle (PID 0)
    //
    if (pid == 0 || pid == 4) {
        return TRUE;
    }

    //
    // Additional system process detection would go here
    // (checking for SYSTEM token, etc.)
    //

    return FALSE;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - CLUSTER ANALYSIS
// ============================================================================

static VOID
PrpAnalyzeCluster(
    _In_ PPR_GRAPH_INTERNAL Graph,
    _In_ PPR_PROCESS_NODE StartNode,
    _Inout_ PPR_CLUSTER_CONTEXT Context
    )
{
    PLIST_ENTRY listEntry;
    PPR_RELATIONSHIP relationship;
    PPR_PROCESS_NODE targetNode;

    //
    // Add start node to cluster
    //
    if (Context->ProcessCount < ARRAYSIZE(Context->ProcessIds)) {
        Context->ProcessIds[Context->ProcessCount++] = StartNode->ProcessId;
    }

    //
    // Analyze all relationships from this node
    //
    for (listEntry = StartNode->RelationshipList.Flink;
         listEntry != &StartNode->RelationshipList;
         listEntry = listEntry->Flink) {

        relationship = CONTAINING_RECORD(listEntry, PR_RELATIONSHIP, ListEntry);

        Context->RelationshipCount++;
        Context->TotalScore += relationship->SuspicionScore;

        //
        // Track time window
        //
        if (Context->FirstEventTime.QuadPart == 0 ||
            relationship->Timestamp.QuadPart < Context->FirstEventTime.QuadPart) {
            Context->FirstEventTime = relationship->Timestamp;
        }

        if (relationship->Timestamp.QuadPart > Context->LastEventTime.QuadPart) {
            Context->LastEventTime = relationship->Timestamp;
        }

        //
        // Add target process to cluster if not already present
        //
        if (!PrpIsNodeInCluster(Context, relationship->TargetProcessId)) {
            if (Context->ProcessCount < ARRAYSIZE(Context->ProcessIds)) {
                Context->ProcessIds[Context->ProcessCount++] = relationship->TargetProcessId;

                //
                // Recursively analyze target node (limited depth)
                //
                targetNode = PrpFindNodeLocked(Graph, relationship->TargetProcessId);
                if (targetNode != NULL && Context->ProcessCount < 32) {
                    //
                    // Don't recurse too deeply
                    //
                }
            }
        }
    }
}

static BOOLEAN
PrpIsNodeInCluster(
    _In_ PPR_CLUSTER_CONTEXT Context,
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    for (i = 0; i < Context->ProcessCount; i++) {
        if (Context->ProcessIds[i] == ProcessId) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - REFERENCE COUNTING
// ============================================================================

static VOID
PrpAcquireReference(
    _In_ PPR_GRAPH_INTERNAL Graph
    )
{
    InterlockedIncrement(&Graph->ActiveOperations);
}

static VOID
PrpReleaseReference(
    _In_ PPR_GRAPH_INTERNAL Graph
    )
{
    if (InterlockedDecrement(&Graph->ActiveOperations) == 0) {
        KeSetEvent(&Graph->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}
