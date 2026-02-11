/*++
    ShadowStrike Next-Generation Antivirus
    Module: ConnectionTracker.h

    Purpose: Network connection state tracking for monitoring
             all inbound and outbound network activity.

    Architecture:
    - Per-process connection tracking
    - Connection lifetime management with deterministic refcounting
    - Flow correlation with processes
    - Bandwidth and data transfer monitoring

    Lock Ordering Hierarchy (acquire in this order, never invert):
      1. ConnectionListLock          (global connection list)
      2. ConnectionHash.Lock         (5-tuple hash)
      3. FlowHash.Lock               (flow ID hash)
      4. ProcessListLock             (global process list)
      5. ProcessHash.Lock            (process hash - internal)
      6. CT_PROCESS_CONTEXT.ConnectionLock (per-process spin lock)
      7. CallbackLock                (internal callback array)

    Callbacks MUST NOT call back into the tracker.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "../../Shared/NetworkTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define CT_POOL_TAG_CONN        'NCTC'  // Connection Tracker - Connection
#define CT_POOL_TAG_FLOW        'FCTC'  // Connection Tracker - Flow
#define CT_POOL_TAG_PROC        'PCTC'  // Connection Tracker - Process
#define CT_POOL_TAG_WORK        'WCTC'  // Connection Tracker - Work Item
#define CT_POOL_TAG_SNAP        'SCTC'  // Connection Tracker - Snapshot

//=============================================================================
// Configuration Constants
//=============================================================================

#define CT_MAX_CONNECTIONS              65536
#define CT_MAX_CONNECTIONS_PER_PROCESS  4096
#define CT_CONNECTION_TIMEOUT_MS        300000  // 5 minutes idle
#define CT_HASH_BUCKET_COUNT            4096
#define CT_FLOW_SAMPLE_INTERVAL_MS      1000

//=============================================================================
// Connection State
//=============================================================================

typedef enum _CT_CONNECTION_STATE {
    CtState_New = 0,
    CtState_Connecting,
    CtState_Connected,
    CtState_Established,
    CtState_Closing,
    CtState_Closed,
    CtState_TimedOut,
    CtState_Blocked,
    CtState_Error
} CT_CONNECTION_STATE;

//=============================================================================
// Connection Direction
//=============================================================================

typedef enum _CT_DIRECTION {
    CtDirection_Unknown = 0,
    CtDirection_Inbound,
    CtDirection_Outbound,
    CtDirection_Both                    // For established connections
} CT_DIRECTION;

//=============================================================================
// Connection Flags
//=============================================================================

typedef enum _CT_CONNECTION_FLAGS {
    CtFlag_None             = 0x00000000,
    CtFlag_IPv6             = 0x00000001,
    CtFlag_Loopback         = 0x00000002,
    CtFlag_Multicast        = 0x00000004,
    CtFlag_Broadcast        = 0x00000008,
    CtFlag_Encrypted        = 0x00000010,   // TLS/SSL detected
    CtFlag_Suspicious       = 0x00000020,
    CtFlag_Blocked          = 0x00000040,
    CtFlag_Allowed          = 0x00000080,
    CtFlag_System           = 0x00000100,   // System process
    CtFlag_Service          = 0x00000200,   // Windows service
    CtFlag_HighFrequency    = 0x00000400,   // High packet rate
    CtFlag_LargeTransfer    = 0x00000800,   // Large data transfer
    CtFlag_RemovedFromLists = 0x00001000,   // Unlinked from all tracking
} CT_CONNECTION_FLAGS;

//=============================================================================
// Flow Statistics
//=============================================================================

typedef struct _CT_FLOW_STATS {
    //
    // Packet counts (lock-free via Interlocked)
    //
    volatile LONG64 PacketsSent;
    volatile LONG64 PacketsReceived;

    //
    // Byte counts (lock-free via Interlocked)
    //
    volatile LONG64 BytesSent;
    volatile LONG64 BytesReceived;

    //
    // Rate tracking
    //
    ULONG CurrentSendRate;              // Bytes/sec
    ULONG CurrentRecvRate;              // Bytes/sec
    ULONG PeakSendRate;
    ULONG PeakRecvRate;

    //
    // Timing — use InterlockedExchange64 for LastPacketTime
    //
    LARGE_INTEGER FirstPacketTime;
    volatile LONG64 LastPacketTime;      // 100ns ticks, atomic
    volatile LONG IdleTimeMs;

} CT_FLOW_STATS, *PCT_FLOW_STATS;

//=============================================================================
// Connection Entry
//=============================================================================

typedef struct _CT_CONNECTION {
    //
    // Connection identification
    //
    ULONG64 ConnectionId;
    UINT64 FlowId;                      // WFP flow ID
    UINT16 LayerId;                     // WFP layer

    //
    // Connection details — State and Flags are volatile for atomic access
    //
    volatile LONG State;                // CT_CONNECTION_STATE via InterlockedExchange
    CT_DIRECTION Direction;
    volatile LONG Flags;                // CT_CONNECTION_FLAGS via InterlockedOr/And
    UCHAR Protocol;                     // IPPROTO_*

    //
    // Local endpoint
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } LocalAddress;
    USHORT LocalPort;
    BOOLEAN IsIPv6;

    //
    // Remote endpoint
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    CHAR RemoteHostname[256];           // If resolved

    //
    // Process context — ProcessId is immutable after creation.
    // ProcessContextRef is a referenced pointer; holds a refcount
    // on the CT_PROCESS_CONTEXT it points to. Only accessed/cleared
    // under the global connection list lock or during final free.
    //
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    UNICODE_STRING ProcessPath;
    struct _CT_PROCESS_CONTEXT* ProcessContextRef;

    //
    // Flow statistics
    //
    CT_FLOW_STATS Stats;

    //
    // TLS information (allocated on demand — NULL if no TLS)
    //
    struct _CT_TLS_INFO* TlsInfo;

    //
    // Timing
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ConnectTime;
    LARGE_INTEGER CloseTime;

    //
    // Suspicion tracking
    //
    ULONG SuspicionScore;
    ULONG SuspicionFlags;

    //
    // Reference counting — free on drop to zero
    //
    volatile LONG RefCount;

    //
    // Back-pointer to owning tracker (for release-triggered free)
    //
    struct _CT_TRACKER* OwnerTracker;

    //
    // List linkage — each entry is for exactly one list
    //
    LIST_ENTRY GlobalListEntry;
    LIST_ENTRY ProcessListEntry;
    LIST_ENTRY HashListEntry;

} CT_CONNECTION, *PCT_CONNECTION;

//=============================================================================
// TLS Information (heap-allocated on demand)
//=============================================================================

typedef struct _CT_TLS_INFO {
    BOOLEAN IsTLS;
    USHORT TLSVersion;
    CHAR CipherSuite[64];
    CHAR ServerName[256];               // SNI
    UCHAR JA3Hash[16];                  // MD5 of JA3
    UCHAR JA3SHash[16];                 // MD5 of JA3S
} CT_TLS_INFO, *PCT_TLS_INFO;

//=============================================================================
// Process Network Context
//=============================================================================

typedef struct _CT_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    PEPROCESS Process;                  // Referenced via ObReferenceObject
    UNICODE_STRING ProcessName;

    //
    // Connections (protected by ConnectionLock spin lock)
    //
    LIST_ENTRY ConnectionList;
    KSPIN_LOCK ConnectionLock;
    volatile LONG ConnectionCount;
    volatile LONG ActiveConnectionCount;

    //
    // Aggregate statistics (lock-free via Interlocked)
    //
    volatile LONG64 TotalBytesSent;
    volatile LONG64 TotalBytesReceived;
    volatile LONG64 TotalConnections;

    //
    // Per-port tracking
    //
    ULONG UniqueRemotePorts;
    ULONG UniqueLocalPorts;

    //
    // Behavior tracking
    //
    ULONG ConnectionsPerMinute;
    ULONG PortScoreIndicator;
    BOOLEAN HighNetworkActivity;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage — separate entries for hash and global list
    //
    LIST_ENTRY HashListEntry;           // ProcessHash bucket
    LIST_ENTRY GlobalListEntry;         // Public.ProcessList

} CT_PROCESS_CONTEXT, *PCT_PROCESS_CONTEXT;

//=============================================================================
// Connection Tracker (public portion)
//=============================================================================

typedef struct _CT_TRACKER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;

    //
    // Connection list
    //
    LIST_ENTRY ConnectionList;
    EX_PUSH_LOCK ConnectionListLock;
    volatile LONG ConnectionCount;

    //
    // Connection hash table (by 5-tuple)
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
    } ConnectionHash;

    //
    // Flow ID lookup
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
    } FlowHash;

    //
    // Process contexts
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;

    //
    // ID generation
    //
    volatile LONG64 NextConnectionId;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    ULONG CleanupIntervalMs;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalConnections;
        volatile LONG64 ActiveConnections;
        volatile LONG64 BlockedConnections;
        volatile LONG64 TotalBytesSent;
        volatile LONG64 TotalBytesReceived;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        ULONG MaxConnections;
        ULONG ConnectionTimeoutMs;
        BOOLEAN TrackAllProcesses;
        BOOLEAN EnableTLSInspection;
    } Config;

} CT_TRACKER, *PCT_TRACKER;

//=============================================================================
// Callback Types
//=============================================================================

// WARNING: Callbacks MUST NOT call back into any Ct* API — deadlock will result.
typedef VOID (*CT_CONNECTION_CALLBACK)(
    _In_ PCT_CONNECTION Connection,
    _In_ CT_CONNECTION_STATE OldState,
    _In_ CT_CONNECTION_STATE NewState,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
CtInitialize(
    _Out_ PCT_TRACKER* Tracker
    );

VOID
CtShutdown(
    _Inout_ PCT_TRACKER Tracker
    );

//=============================================================================
// Public API - Connection Management
//=============================================================================

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
    );

NTSTATUS
CtUpdateConnectionState(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _In_ CT_CONNECTION_STATE NewState
    );

NTSTATUS
CtRemoveConnection(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId
    );

//=============================================================================
// Public API - Connection Lookup
//=============================================================================

NTSTATUS
CtFindByFlowId(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _Out_ PCT_CONNECTION* Connection
    );

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
    );

//=============================================================================
// Public API - Statistics Update
//=============================================================================

NTSTATUS
CtUpdateStats(
    _In_ PCT_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _In_ SIZE_T BytesSent,
    _In_ SIZE_T BytesReceived,
    _In_ ULONG PacketsSent,
    _In_ ULONG PacketsReceived
    );

//=============================================================================
// Public API - Process Queries
//=============================================================================

NTSTATUS
CtGetProcessConnections(
    _In_ PCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxConnections, *ConnectionCount) PCT_CONNECTION* Connections,
    _In_ ULONG MaxConnections,
    _Out_ PULONG ConnectionCount
    );

NTSTATUS
CtGetProcessNetworkStats(
    _In_ PCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PULONG64 BytesSent,
    _Out_ PULONG64 BytesReceived,
    _Out_ PULONG ActiveConnections
    );

//=============================================================================
// Public API - Enumeration
//=============================================================================

// WARNING: Callback MUST NOT call back into any Ct* API.
typedef BOOLEAN (*CT_ENUM_CALLBACK)(
    _In_ PCT_CONNECTION Connection,
    _In_opt_ PVOID Context
    );

NTSTATUS
CtEnumerateConnections(
    _In_ PCT_TRACKER Tracker,
    _In_ CT_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
CtRegisterCallback(
    _In_ PCT_TRACKER Tracker,
    _In_ CT_CONNECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
CtUnregisterCallback(
    _In_ PCT_TRACKER Tracker,
    _In_ CT_CONNECTION_CALLBACK Callback
    );

//=============================================================================
// Public API - Reference Counting
//=============================================================================

VOID
CtAddRef(
    _In_ PCT_CONNECTION Connection
    );

VOID
CtRelease(
    _In_ PCT_CONNECTION Connection
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _CT_STATISTICS {
    ULONG ActiveConnections;
    ULONG64 TotalConnections;
    ULONG64 BlockedConnections;
    ULONG64 TotalBytesSent;
    ULONG64 TotalBytesReceived;
    ULONG TrackedProcesses;
    LARGE_INTEGER UpTime;
} CT_STATISTICS, *PCT_STATISTICS;

NTSTATUS
CtGetStatistics(
    _In_ PCT_TRACKER Tracker,
    _Out_ PCT_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
