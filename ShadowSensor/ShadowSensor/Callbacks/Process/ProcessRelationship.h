/*++
    ShadowStrike Next-Generation Antivirus
    Module: ProcessRelationship.h - Process graph and relationship tracking
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define PR_POOL_TAG 'LERP'
#define PR_MAX_CHILDREN 256
#define PR_MAX_CONNECTIONS 64

typedef enum _PR_RELATIONSHIP_TYPE {
    PrRelation_ParentChild = 0,
    PrRelation_Injected,
    PrRelation_RemoteThread,
    PrRelation_SharedSection,
    PrRelation_HandleDuplication,
    PrRelation_DebugRelation,
} PR_RELATIONSHIP_TYPE;

typedef struct _PR_RELATIONSHIP {
    PR_RELATIONSHIP_TYPE Type;
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    LARGE_INTEGER Timestamp;
    ULONG SuspicionScore;
    LIST_ENTRY ListEntry;
} PR_RELATIONSHIP, *PPR_RELATIONSHIP;

typedef struct _PR_PROCESS_NODE {
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
    LARGE_INTEGER CreateTime;
    
    // Parent link
    HANDLE ParentId;
    
    // Children
    HANDLE Children[PR_MAX_CHILDREN];
    ULONG ChildCount;
    
    // Relationships
    LIST_ENTRY RelationshipList;
    volatile LONG RelationshipCount;
    
    // Graph metrics
    ULONG DepthFromRoot;
    ULONG SubtreeSize;
    BOOLEAN IsOrphan;
    
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
} PR_PROCESS_NODE, *PPR_PROCESS_NODE;

typedef struct _PR_GRAPH {
    BOOLEAN Initialized;
    
    // All nodes
    LIST_ENTRY NodeList;
    EX_PUSH_LOCK NodeLock;
    volatile LONG NodeCount;
    
    // Hash for fast lookup
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } NodeHash;
    
    // Relationship tracking
    LIST_ENTRY RelationshipList;
    EX_PUSH_LOCK RelationshipLock;
    
    struct {
        volatile LONG64 NodesTracked;
        volatile LONG64 RelationshipsTracked;
        LARGE_INTEGER StartTime;
    } Stats;
} PR_GRAPH, *PPR_GRAPH;

NTSTATUS PrInitialize(_Out_ PPR_GRAPH* Graph);
VOID PrShutdown(_Inout_ PPR_GRAPH Graph);
NTSTATUS PrAddProcess(_In_ PPR_GRAPH Graph, _In_ HANDLE ProcessId, _In_ HANDLE ParentId, _In_ PUNICODE_STRING ImageName);
NTSTATUS PrRemoveProcess(_In_ PPR_GRAPH Graph, _In_ HANDLE ProcessId);
NTSTATUS PrAddRelationship(_In_ PPR_GRAPH Graph, _In_ PR_RELATIONSHIP_TYPE Type, _In_ HANDLE SourceId, _In_ HANDLE TargetId);
NTSTATUS PrGetNode(_In_ PPR_GRAPH Graph, _In_ HANDLE ProcessId, _Out_ PPR_PROCESS_NODE* Node);
NTSTATUS PrGetChildren(_In_ PPR_GRAPH Graph, _In_ HANDLE ProcessId, _Out_writes_to_(Max, *Count) HANDLE* Children, _In_ ULONG Max, _Out_ PULONG Count);
NTSTATUS PrGetRelationships(_In_ PPR_GRAPH Graph, _In_ HANDLE ProcessId, _Out_writes_to_(Max, *Count) PPR_RELATIONSHIP* Relations, _In_ ULONG Max, _Out_ PULONG Count);
NTSTATUS PrFindSuspiciousClusters(_In_ PPR_GRAPH Graph, _Out_writes_to_(Max, *Count) HANDLE* Processes, _In_ ULONG Max, _Out_ PULONG Count);

#ifdef __cplusplus
}
#endif
