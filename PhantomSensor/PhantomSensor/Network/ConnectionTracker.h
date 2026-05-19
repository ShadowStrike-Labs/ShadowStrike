/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
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

#include <ntifs.h>
#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)   // nameless struct/union â€” ndis.h
#pragma warning(disable:4324)   // structure padded â€” ndis.h / fltKernel.h
#ifndef NDIS_SUPPORT_NDIS650
#define NDIS_SUPPORT_NDIS650 1
#endif
#include <ndis.h>
#pragma warning(pop)
#include <fwpsk.h>
#pragma warning(push)
#pragma warning(disable:4324)   // structure padded â€” fltKernel.h via NetworkTypes.h
#include <fwpmk.h>
#include "../../Shared/NetworkTypes.h"
#pragma warning(pop)

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
    // Timing â€” use InterlockedExchange64 for LastPacketTime
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
    // Connection details â€” State and Flags are volatile for atomic access
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
    CHAR RemoteHostname[256];           // If resolved, always NUL-terminated

    //
    // Process context â€” ProcessId is immutable after creation.
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
    // TLS information (allocated on demand â€” NULL if no TLS)
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
    // Reference counting â€” free on drop to zero
    //
    volatile LONG RefCount;

    //
    // Back-pointer to owning tracker (for release-triggered free)
    //
    struct _CT_TRACKER* OwnerTracker;

    //
    // List linkage â€” each entry is for exactly one list
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
    // List linkage â€” separate entries for hash and global list
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
    // Cleanup timer (managed by TimerManager)
    //
    ULONG CleanupTimerId;
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

} CT_TRACKER, *PCONNECTION_TRACKER;

//=============================================================================
// Callback Types
//=============================================================================

// WARNING: Callbacks MUST NOT call back into any Ct* API â€” deadlock will result.
typedef VOID (*CT_CONNECTION_CALLBACK)(
    _In_ PCT_CONNECTION Connection,
    _In_ CT_CONNECTION_STATE OldState,
    _In_ CT_CONNECTION_STATE NewState,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

/**
 * @brief Initialize the connection tracker.
 * 
 * Allocates and initializes all tracking structures, hash tables, lookaside
 * lists, and starts the periodic cleanup timer. Must be called at PASSIVE_LEVEL.
 * 
 * @param Tracker Receives pointer to initialized tracker on success
 * @return STATUS_SUCCESS or error code
 * 
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CtInitialize(
    _Out_ PCONNECTION_TRACKER* Tracker
    );

/**
 * @brief Shutdown and free the connection tracker.
 * 
 * Stops cleanup timer, drains all connections and process contexts, and frees
 * all resources. May be called at IRQL <= DISPATCH_LEVEL (acquires spinlocks).
 * 
 * @param Tracker Tracker to shutdown (invalidated on return)
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
CtShutdown(
    _Inout_ PCONNECTION_TRACKER Tracker
    );

//=============================================================================
// Public API - Connection Management
//=============================================================================

/**
 * @brief Create and track a new network connection.
 * 
 * Allocates a connection entry, indexes it by FlowId and 5-tuple, associates
 * with process context, and returns a referenced pointer. Caller must release
 * via CtRelease when done.
 * 
 * @param Tracker Initialized tracker
 * @param FlowId WFP flow identifier (must be unique)
 * @param ProcessId Originating process ID
 * @param Direction Connection direction
 * @param Protocol IPPROTO_TCP, IPPROTO_UDP, etc.
 * @param LocalAddress Pointer to IN_ADDR or IN6_ADDR (kernel mode)
 * @param LocalPort Local port in host byte order
 * @param RemoteAddress Pointer to IN_ADDR or IN6_ADDR (kernel mode)
 * @param RemotePort Remote port in host byte order
 * @param IsIPv6 TRUE for IPv6, FALSE for IPv4
 * @param Connection Receives referenced connection pointer on success
 * @return STATUS_SUCCESS, STATUS_DUPLICATE_OBJECTID, or error
 * 
 * @irql IRQL <= DISPATCH_LEVEL (acquires spinlocks internally)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
CtCreateConnection(
    _In_ PCONNECTION_TRACKER Tracker,
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

/**
 * @brief Update connection state atomically.
 * 
 * @param Tracker Initialized tracker
 * @param FlowId Flow identifier
 * @param NewState New state to set
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
CtUpdateConnectionState(
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _In_ CT_CONNECTION_STATE NewState
    );

/**
 * @brief Remove connection from tracking.
 * 
 * Transitions to Closed state, removes from all indices, and releases list reference.
 * Connection is freed when all external references are released.
 * 
 * @param Tracker Initialized tracker
 * @param FlowId Flow identifier
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
CtRemoveConnection(
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ UINT64 FlowId
    );

//=============================================================================
// Public API - Connection Lookup
//=============================================================================

/**
 * @brief Find connection by WFP flow ID.
 * 
 * Returns a referenced pointer; caller must release via CtRelease.
 * 
 * @param Tracker Initialized tracker
 * @param FlowId Flow identifier
 * @param Connection Receives referenced connection pointer on success
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
CtFindByFlowId(
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ UINT64 FlowId,
    _Out_ PCT_CONNECTION* Connection
    );

/**
 * @brief Find connection by 5-tuple endpoints.
 * 
 * Returns a referenced pointer; caller must release via CtRelease.
 * 
 * @param Tracker Initialized tracker
 * @param LocalAddress Pointer to IN_ADDR or IN6_ADDR
 * @param LocalPort Local port in host byte order
 * @param RemoteAddress Pointer to IN_ADDR or IN6_ADDR
 * @param RemotePort Remote port in host byte order
 * @param Protocol IPPROTO_*
 * @param IsIPv6 TRUE for IPv6, FALSE for IPv4
 * @param Connection Receives referenced connection pointer on success
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
CtFindByEndpoints(
    _In_ PCONNECTION_TRACKER Tracker,
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

/**
 * @brief Update connection statistics atomically.
 * 
 * Increments byte and packet counters, updates last activity timestamp.
 * All updates are lock-free via Interlocked operations.
 * 
 * @param Tracker Initialized tracker
 * @param FlowId Flow identifier
 * @param BytesSent Bytes sent since last update (clamped to LONG64_MAX)
 * @param BytesReceived Bytes received since last update (clamped to LONG64_MAX)
 * @param PacketsSent Packets sent
 * @param PacketsReceived Packets received
 * @return STATUS_SUCCESS, STATUS_NOT_FOUND, or error
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
CtUpdateStats(
    _In_ PCONNECTION_TRACKER Tracker,
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
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxConnections, *ConnectionCount) PCT_CONNECTION* Connections,
    _In_ ULONG MaxConnections,
    _Out_ PULONG ConnectionCount
    );

NTSTATUS
CtGetProcessNetworkStats(
    _In_ PCONNECTION_TRACKER Tracker,
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
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ CT_ENUM_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
CtRegisterCallback(
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ CT_CONNECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
CtUnregisterCallback(
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ CT_CONNECTION_CALLBACK Callback
    );

//=============================================================================
// Public API - Reference Counting
//=============================================================================

/**
 * @brief Increment connection reference count.
 * 
 * Must be called for every pointer copy that will be held across potential
 * blocking operations or async callbacks.
 * 
 * @param Connection Connection to reference (must not be NULL)
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
CtAddRef(
    _In_ PCT_CONNECTION Connection
    );

/**
 * @brief Decrement connection reference count.
 * 
 * Frees connection when refcount drops to zero. Connection must have been
 * removed from all lists before the last reference is released.
 * 
 * @param Connection Connection to release (NULL is safe)
 * 
 * @irql IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
CtRelease(
    _In_opt_ PCT_CONNECTION Connection
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
} CT_STATISTICS, *PCONNECTION_STATISTICS;

NTSTATUS
CtGetStatistics(
    _In_ PCONNECTION_TRACKER Tracker,
    _Out_ PCONNECTION_STATISTICS Stats
    );

//=============================================================================
// Public API - Process Lifecycle
//=============================================================================

/**
 * @brief Notification that a process has terminated.
 * 
 * Removes process context from tracking. Stale connections referencing the
 * process will be cleaned up by the periodic timer.
 * 
 * @param Tracker Initialized tracker
 * @param ProcessId Terminated process ID
 * 
 * @irql IRQL <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
CtProcessTerminated(
    _In_ PCONNECTION_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

#ifdef __cplusplus
}
#endif
