/*++
    ShadowStrike Next-Generation Antivirus
    Module: ProcessRelationship.h - Process graph and relationship tracking

    ENTERPRISE-GRADE IMPLEMENTATION

    This module provides comprehensive process relationship tracking with:
    - Reference-counted nodes for safe concurrent access
    - Dual list entries for relationships (node-local and global)
    - IRQL-safe design with documented requirements
    - Complete input validation and security hardening

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags and limits
//
#define PR_POOL_TAG                     'LERP'
#define PR_MAX_CHILDREN                 256
#define PR_MAX_CONNECTIONS              64
#define PR_MAX_NODES                    8192
#define PR_MAX_RELATIONSHIPS            32768
#define PR_HASH_BUCKET_COUNT            256

//
// Signature for structure validation
//
#define PR_GRAPH_SIGNATURE              0x50524750  // 'PRGP'
#define PR_NODE_SIGNATURE               0x50524E44  // 'PRND'

//
// Relationship types for process graph edges
//
typedef enum _PR_RELATIONSHIP_TYPE {
    PrRelation_ParentChild = 0,
    PrRelation_Injected,
    PrRelation_RemoteThread,
    PrRelation_SharedSection,
    PrRelation_HandleDuplication,
    PrRelation_DebugRelation,
    PrRelation_MaxType
} PR_RELATIONSHIP_TYPE;

//
// Relationship structure with DUAL list entries to avoid corruption
// NodeListEntry: Links to source node's relationship list
// GlobalListEntry: Links to graph's global relationship list
//
typedef struct _PR_RELATIONSHIP {
    //
    // Relationship data
    //
    PR_RELATIONSHIP_TYPE Type;
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    LARGE_INTEGER Timestamp;
    ULONG SuspicionScore;

    //
    // CRITICAL: Two separate list entries for two different lists
    // Using single ListEntry for multiple lists causes corruption
    //
    LIST_ENTRY NodeListEntry;       // Links in source node's RelationshipList
    LIST_ENTRY GlobalListEntry;     // Links in graph's global RelationshipList

} PR_RELATIONSHIP, *PPR_RELATIONSHIP;

//
// Copied relationship data for safe return to callers
// Avoids dangling pointer issues when returning relationship info
//
typedef struct _PR_RELATIONSHIP_INFO {
    PR_RELATIONSHIP_TYPE Type;
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    LARGE_INTEGER Timestamp;
    ULONG SuspicionScore;
} PR_RELATIONSHIP_INFO, *PPR_RELATIONSHIP_INFO;

//
// Process node with reference counting for safe concurrent access
//
typedef struct _PR_PROCESS_NODE {
    //
    // Validation signature
    //
    ULONG Signature;

    //
    // Reference count for safe access after lock release
    // Node is freed when RefCount reaches 0 AND removed from graph
    //
    volatile LONG RefCount;

    //
    // Flag indicating node has been removed from graph
    // Set under exclusive lock, prevents new references
    //
    volatile LONG Removed;

    //
    // Process identification
    //
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
    LARGE_INTEGER CreateTime;

    //
    // Parent link
    //
    HANDLE ParentId;

    //
    // Children array (fixed size for simplicity)
    //
    HANDLE Children[PR_MAX_CHILDREN];
    volatile LONG ChildCount;

    //
    // Relationships originating from this process
    //
    LIST_ENTRY RelationshipList;
    volatile LONG RelationshipCount;
    EX_SPIN_LOCK RelationshipSpinLock;  // Protects RelationshipList

    //
    // Graph metrics
    //
    ULONG DepthFromRoot;
    ULONG SubtreeSize;
    BOOLEAN IsOrphan;

    //
    // Session information (cached for IRQL safety)
    //
    ULONG SessionId;
    BOOLEAN IsSystemProcess;

    //
    // List entries for graph membership
    //
    LIST_ENTRY ListEntry;       // Graph's NodeList
    LIST_ENTRY HashEntry;       // Hash bucket list

} PR_PROCESS_NODE, *PPR_PROCESS_NODE;

//
// Copied node data for safe return to callers
//
typedef struct _PR_NODE_INFO {
    HANDLE ProcessId;
    HANDLE ParentId;
    WCHAR ImageName[260];
    USHORT ImageNameLength;
    LARGE_INTEGER CreateTime;
    ULONG ChildCount;
    ULONG RelationshipCount;
    ULONG DepthFromRoot;
    ULONG SubtreeSize;
    BOOLEAN IsOrphan;
    ULONG SessionId;
    BOOLEAN IsSystemProcess;
} PR_NODE_INFO, *PPR_NODE_INFO;

//
// Graph statistics
//
typedef struct _PR_GRAPH_STATS {
    volatile LONG64 NodesTracked;
    volatile LONG64 NodesRemoved;
    volatile LONG64 RelationshipsTracked;
    volatile LONG64 RelationshipsRemoved;
    volatile LONG64 RelationshipsByType[PrRelation_MaxType];
    LARGE_INTEGER StartTime;
    volatile LONG64 LookupCount;
    volatile LONG64 LookupHits;
} PR_GRAPH_STATS, *PPR_GRAPH_STATS;

//
// Main graph structure (public portion)
//
typedef struct _PR_GRAPH {
    //
    // Initialization state
    //
    BOOLEAN Initialized;

    //
    // All nodes in graph
    //
    LIST_ENTRY NodeList;
    EX_PUSH_LOCK NodeLock;
    volatile LONG NodeCount;

    //
    // Hash table for O(1) process lookup
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } NodeHash;

    //
    // Global relationship list (all relationships)
    //
    LIST_ENTRY RelationshipList;
    EX_PUSH_LOCK RelationshipLock;
    volatile LONG RelationshipCount;

    //
    // Statistics
    //
    PR_GRAPH_STATS Stats;

} PR_GRAPH, *PPR_GRAPH;

// ============================================================================
// PUBLIC API - All functions require IRQL <= APC_LEVEL unless noted
// ============================================================================

/**
 * @brief Initialize a new process relationship graph.
 *
 * @param[out] Graph    Receives pointer to initialized graph.
 * @return STATUS_SUCCESS or error code.
 *
 * @irql PASSIVE_LEVEL only
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PrInitialize(
    _Out_ PPR_GRAPH* Graph
    );

/**
 * @brief Shutdown and free graph resources.
 *
 * Waits for all active operations to complete before freeing.
 *
 * @param[in,out] Graph     Graph to shutdown.
 *
 * @irql PASSIVE_LEVEL only
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PrShutdown(
    _Inout_ PPR_GRAPH Graph
    );

/**
 * @brief Add a process to the graph.
 *
 * @param[in] Graph         Target graph.
 * @param[in] ProcessId     Process ID to add.
 * @param[in] ParentId      Parent process ID (may be NULL).
 * @param[in] ImageName     Process image name (may be NULL).
 * @return STATUS_SUCCESS, STATUS_OBJECT_NAME_EXISTS, or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrAddProcess(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentId,
    _In_opt_ PUNICODE_STRING ImageName
    );

/**
 * @brief Remove a process from the graph.
 *
 * Children are marked as orphans but not removed.
 *
 * @param[in] Graph         Target graph.
 * @param[in] ProcessId     Process ID to remove.
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrRemoveProcess(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Add a relationship between two processes.
 *
 * @param[in] Graph         Target graph.
 * @param[in] Type          Relationship type.
 * @param[in] SourceId      Source process ID.
 * @param[in] TargetId      Target process ID.
 * @return STATUS_SUCCESS or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrAddRelationship(
    _In_ PPR_GRAPH Graph,
    _In_ PR_RELATIONSHIP_TYPE Type,
    _In_ HANDLE SourceId,
    _In_ HANDLE TargetId
    );

/**
 * @brief Get node information by process ID.
 *
 * Returns a COPY of node data, safe to use after call returns.
 *
 * @param[in] Graph         Target graph.
 * @param[in] ProcessId     Process ID to look up.
 * @param[out] NodeInfo     Receives copy of node information.
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrGetNodeInfo(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_ PPR_NODE_INFO NodeInfo
    );

/**
 * @brief Get children of a process.
 *
 * @param[in] Graph         Target graph.
 * @param[in] ProcessId     Parent process ID.
 * @param[out] Children     Buffer to receive child PIDs.
 * @param[in] MaxCount      Maximum entries in Children buffer.
 * @param[out] Count        Receives actual count copied.
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrGetChildren(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxCount, *Count) HANDLE* Children,
    _In_ ULONG MaxCount,
    _Out_ PULONG Count
    );

/**
 * @brief Get relationships for a process.
 *
 * Returns COPIES of relationship data, safe to use after call returns.
 *
 * @param[in] Graph         Target graph.
 * @param[in] ProcessId     Process ID.
 * @param[out] Relations    Buffer to receive relationship info.
 * @param[in] MaxCount      Maximum entries in Relations buffer.
 * @param[out] Count        Receives actual count copied.
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrGetRelationships(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxCount, *Count) PR_RELATIONSHIP_INFO* Relations,
    _In_ ULONG MaxCount,
    _Out_ PULONG Count
    );

/**
 * @brief Find processes that are part of suspicious activity clusters.
 *
 * Uses graph analysis to identify groups of related suspicious activity.
 *
 * @param[in] Graph         Target graph.
 * @param[out] Processes    Buffer to receive suspicious PIDs.
 * @param[in] MaxCount      Maximum entries in Processes buffer.
 * @param[out] Count        Receives actual count found.
 * @return STATUS_SUCCESS or error.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrFindSuspiciousClusters(
    _In_ PPR_GRAPH Graph,
    _Out_writes_to_(MaxCount, *Count) HANDLE* Processes,
    _In_ ULONG MaxCount,
    _Out_ PULONG Count
    );

/**
 * @brief Get graph statistics.
 *
 * @param[in] Graph         Target graph.
 * @param[out] Stats        Receives statistics.
 * @return STATUS_SUCCESS or error.
 *
 * @irql Any (lock-free read of atomics)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PrGetStatistics(
    _In_ PPR_GRAPH Graph,
    _Out_ PPR_GRAPH_STATS Stats
    );

//
// Legacy API - maintained for compatibility but deprecated
// Use PrGetNodeInfo instead
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PrGetNode(
    _In_ PPR_GRAPH Graph,
    _In_ HANDLE ProcessId,
    _Out_ PPR_PROCESS_NODE* Node
    );

#ifdef __cplusplus
}
#endif
