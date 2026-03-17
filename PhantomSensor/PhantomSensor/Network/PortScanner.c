// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
    Module: PortScanner.c

    Purpose: Enterprise-grade port scan detection for reconnaissance identification.

    This module provides comprehensive port scanning detection capabilities:
    - Vertical scan detection (single host, multiple ports)
    - Horizontal scan detection (multiple hosts, same port - host sweep)
    - TCP Connect scan detection
    - TCP SYN/Half-open scan detection via flag classification
    - TCP FIN/XMAS/NULL stealth scan detection via flag classification
    - UDP scan detection
    - Service probing detection
    - Per-process connection behavior tracking with PID-reuse protection
    - Time-window based statistical analysis with sliding window cleanup
    - Hash-table based port/host lookup for O(1) performance
    - PASSIVE_LEVEL cleanup via work items (no DPC lock violations)
    - Proper drain/quiesce on shutdown

    Lock Ordering:
    1. Detector->SourceListLock (outermost)
    2. Source->ConnectionLock (innermost)
    Never acquire SourceListLock while holding ConnectionLock.

    IRQL Contract:
    All public APIs require IRQL <= APC_LEVEL (PASSIVE_LEVEL preferred).
    Cleanup runs at PASSIVE_LEVEL via TimerManager (TmFlag_WorkItemCallback).

    MITRE ATT&CK Coverage:
    - T1046: Network Service Discovery
    - T1018: Remote System Discovery
    - T1135: Network Share Discovery

    Copyright (c) ShadowStrike Team
--*/

#pragma warning(push)
#pragma warning(disable: 4324) // structure was padded due to alignment specifier
#include "PortScanner.h"
#pragma warning(pop)

#include <ntstrsafe.h>
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Tracing/Trace.h"
#include "../Sync/TimerManager.h"
#include "../Core/DriverEntry.h"
#include "../Exclusions/ExclusionManager.h"
#include "../Behavioral/BehaviorEngine.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SsPsInitialize)
#pragma alloc_text(PAGE, SsPsShutdown)
#pragma alloc_text(PAGE, SsPsRecordConnection)
#pragma alloc_text(PAGE, SsPsCheckForScan)
#pragma alloc_text(PAGE, SsPsGetStatistics)
#pragma alloc_text(PAGE, SsPsFreeResult)
#endif

//=============================================================================
// Internal Configuration Constants
//=============================================================================

#define SSPS_MAX_PORTS_PER_SOURCE         8192
#define SSPS_MAX_HOSTS_PER_SOURCE         4096
#define SSPS_MAX_CONNECTIONS_PER_SOURCE   65536
#define SSPS_CLEANUP_INTERVAL_MS          30000    // 30 seconds
#define SSPS_SOURCE_EXPIRY_MS             300000   // 5 minutes idle
#define SSPS_SHUTDOWN_DRAIN_TIMEOUT_MS    5000     // 5 second drain

//
// Detection thresholds
//
#define SSPS_VERTICAL_SCAN_THRESHOLD      20
#define SSPS_HORIZONTAL_SCAN_THRESHOLD    10
#define SSPS_RAPID_CONNECT_THRESHOLD      100
#define SSPS_FAILURE_RATE_THRESHOLD       80
#define SSPS_STEALTH_SCAN_THRESHOLD       5

//
// Confidence score weights
//
//
// Confidence scoring weights â€” each factor normalized to [0..30] range
// so no single factor can saturate the 0â€“100 confidence score alone.
//
#define SSPS_WEIGHT_UNIQUE_PORTS          1
#define SSPS_WEIGHT_UNIQUE_HOSTS          1
#define SSPS_WEIGHT_FAILURE_RATE          1
#define SSPS_WEIGHT_RAPID_CONNECTIONS     1
#define SSPS_WEIGHT_STEALTH_TECHNIQUE     1

//
// Hash table bucket counts (power of 2 for fast modulo)
//
#define SSPS_PORT_HASH_BUCKETS    256
#define SSPS_HOST_HASH_BUCKETS    128

//
// Common scanning tool port lists (for scan fingerprinting bonus)
//
static const USHORT g_CommonScanPorts[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
};
#define SSPS_COMMON_SCAN_PORTS_COUNT ARRAYSIZE(g_CommonScanPorts)


//=============================================================================
// Internal Structures
//=============================================================================

//
// Individual connection record
//
typedef struct _SSPS_CONNECTION_RECORD {
    LIST_ENTRY ListEntry;

    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    BOOLEAN IsIPv6;

    UCHAR Protocol;       // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    BOOLEAN Successful;
    UCHAR TcpFlags;       // Raw TCP flags for stealth scan classification

    LARGE_INTEGER Timestamp;
} SSPS_CONNECTION_RECORD, *PSSPS_CONNECTION_RECORD;

//
// Tracked unique port entry (lives in hash bucket)
//
typedef struct _SSPS_PORT_ENTRY {
    LIST_ENTRY BucketLink;
    USHORT Port;
    volatile LONG HitCount;
    LARGE_INTEGER FirstSeen;
    volatile LONGLONG LastSeen;   // Updated atomically via InterlockedExchange64
} SSPS_PORT_ENTRY, *PSSPS_PORT_ENTRY;

//
// Tracked unique host entry (lives in hash bucket)
//
typedef struct _SSPS_HOST_ENTRY {
    LIST_ENTRY BucketLink;
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } Address;
    BOOLEAN IsIPv6;
    volatile LONG PortsScanned;
    LARGE_INTEGER FirstSeen;
    volatile LONGLONG LastSeen;   // Updated atomically
} SSPS_HOST_ENTRY, *PSSPS_HOST_ENTRY;

//
// Simple hash table: array of list heads
//
typedef struct _SSPS_HASH_TABLE {
    ULONG BucketCount;
    LIST_ENTRY Buckets[1];  // Variable-length; actual size = BucketCount
} SSPS_HASH_TABLE, *PSSPS_HASH_TABLE;

//
// Snapshot of window statistics (taken atomically under lock)
//
typedef struct _SSPS_WINDOW_SNAPSHOT {
    LONG TotalConnections;
    LONG SuccessfulConnections;
    LONG FailedConnections;
    LONG TcpSynOnly;
    LONG TcpFinOnly;
    LONG TcpXmas;
    LONG TcpNull;
    LONG UdpConnections;
    LONG UniquePortCount;
    LONG UniqueHostCount;
    LARGE_INTEGER FirstActivity;
    LARGE_INTEGER LastActivity;
} SSPS_WINDOW_SNAPSHOT, *PSSPS_WINDOW_SNAPSHOT;

//
// Per-source tracking context
//
typedef struct _SSPS_SOURCE_CONTEXT {
    LIST_ENTRY ListEntry;

    //
    // Source identification (ProcessId + CreateTime for PID-reuse safety)
    //
    HANDLE ProcessId;
    LARGE_INTEGER ProcessCreateTime;
    WCHAR ProcessName[260];
    WCHAR ProcessPath[520];

    //
    // Connection records
    //
    LIST_ENTRY ConnectionList;
    volatile LONG ConnectionCount;
    EX_PUSH_LOCK ConnectionLock;   // Protects ConnectionList, PortHash, HostHash, WindowStats, timing

    //
    // Hash tables for unique ports and hosts (O(1) lookup)
    //
    PSSPS_HASH_TABLE PortHash;
    volatile LONG UniquePortCount;

    PSSPS_HASH_TABLE HostHash;
    volatile LONG UniqueHostCount;

    //
    // Statistics within current window
    //
    struct {
        volatile LONG TotalConnections;
        volatile LONG SuccessfulConnections;
        volatile LONG FailedConnections;
        volatile LONG TcpSynOnly;
        volatile LONG TcpFinOnly;
        volatile LONG TcpXmas;
        volatile LONG TcpNull;
        volatile LONG UdpConnections;
    } WindowStats;

    //
    // Timing
    //
    LARGE_INTEGER FirstActivity;
    LARGE_INTEGER LastActivity;
    LARGE_INTEGER WindowStart;

    //
    // Detection state
    //
    BOOLEAN ScanDetected;
    SSPS_SCAN_TYPE DetectedScanType;
    ULONG ConfidenceScore;

    //
    // Reference counting for safe lifetime management
    //
    volatile LONG RefCount;
} SSPS_SOURCE_CONTEXT, *PSSPS_SOURCE_CONTEXT;


//=============================================================================
// Forward Declarations
//=============================================================================

static PSSPS_HASH_TABLE
SspsAllocHashTable(
    _In_ ULONG BucketCount,
    _In_ ULONG Tag
    );

static VOID
SspsFreePortHash(
    _In_ PSSPS_HASH_TABLE Table
    );

static VOID
SspsFreeHostHash(
    _In_ PSSPS_HASH_TABLE Table
    );

static VOID
SspsFreeSourceContext(
    _In_ PSSPS_SOURCE_CONTEXT Source
    );

static PSSPS_SOURCE_CONTEXT
SspsFindOrCreateSource(
    _In_ PSSPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER ProcessCreateTime
    );

static VOID
SspsReleaseSource(
    _In_ PSSPS_DETECTOR Detector,
    _In_ PSSPS_SOURCE_CONTEXT Source
    );

static VOID
SspsRecordUniquePort(
    _Inout_ PSSPS_SOURCE_CONTEXT Source,
    _In_ USHORT Port
    );

static VOID
SspsRecordUniqueHost(
    _Inout_ PSSPS_SOURCE_CONTEXT Source,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    );

static VOID
SspsCleanupExpiredRecords(
    _Inout_ PSSPS_SOURCE_CONTEXT Source,
    _In_ PLARGE_INTEGER CurrentTime,
    _In_ ULONG WindowMs
    );

static VOID
SspsAnalyzeScanBehavior(
    _In_ PSSPS_SOURCE_CONTEXT Source,
    _Out_ PSSPS_DETECTION_RESULT Result
    );

static SSPS_SCAN_TYPE
SspsDetermineScanType(
    _In_ PSSPS_WINDOW_SNAPSHOT Snap
    );

static ULONG
SspsCalculateConfidence(
    _In_ PSSPS_WINDOW_SNAPSHOT Snap,
    _In_ SSPS_SCAN_TYPE ScanType,
    _In_ ULONG CommonPortHits
    );

static VOID
SspsGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize,
    _Out_writes_z_(PathSize) PWCHAR ProcessPath,
    _In_ ULONG PathSize
    );

static VOID
SspsClassifyTcpFlags(
    _In_ UCHAR TcpFlags,
    _Inout_ PSSPS_SOURCE_CONTEXT Source
    );

static VOID
SspsReverseClassifyTcpFlags(
    _In_ UCHAR TcpFlags,
    _Inout_ PSSPS_SOURCE_CONTEXT Source
    );

static VOID
SspsSnapshotWindowStats(
    _In_ PSSPS_SOURCE_CONTEXT Source,
    _Out_ PSSPS_WINDOW_SNAPSHOT Snap
    );

//
// Cleanup: TimerManager callback fires at PASSIVE_LEVEL via TmFlag_WorkItemCallback
//
static VOID SspsCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

//
// Page section for all private functions that run at PASSIVE_LEVEL.
// EXCLUDES: FORCEINLINE functions (no discrete function body)
//
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SspsAllocHashTable)
#pragma alloc_text(PAGE, SspsFreePortHash)
#pragma alloc_text(PAGE, SspsFreeHostHash)
#pragma alloc_text(PAGE, SspsFreeSourceContext)
#pragma alloc_text(PAGE, SspsFindOrCreateSource)
#pragma alloc_text(PAGE, SspsReleaseSource)
#pragma alloc_text(PAGE, SspsRecordUniquePort)
#pragma alloc_text(PAGE, SspsRecordUniqueHost)
#pragma alloc_text(PAGE, SspsCleanupExpiredRecords)
#pragma alloc_text(PAGE, SspsAnalyzeScanBehavior)
#pragma alloc_text(PAGE, SspsDetermineScanType)
#pragma alloc_text(PAGE, SspsCalculateConfidence)
#pragma alloc_text(PAGE, SspsGetProcessInfo)
#pragma alloc_text(PAGE, SspsClassifyTcpFlags)
#pragma alloc_text(PAGE, SspsReverseClassifyTcpFlags)
#pragma alloc_text(PAGE, SspsSnapshotWindowStats)
#pragma alloc_text(PAGE, SspsCleanupTimerCallback)
#endif

//=============================================================================
// Hash Table Helpers
//=============================================================================

static
PSSPS_HASH_TABLE
SspsAllocHashTable(
    _In_ ULONG BucketCount,
    _In_ ULONG Tag
    )
{
    PSSPS_HASH_TABLE Table;
    SIZE_T Size;
    ULONG i;

    PAGED_CODE();

    Size = FIELD_OFFSET(SSPS_HASH_TABLE, Buckets) +
           (SIZE_T)BucketCount * sizeof(LIST_ENTRY);

    Table = (PSSPS_HASH_TABLE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, Size, Tag);
    if (Table == NULL) {
        return NULL;
    }

    RtlZeroMemory(Table, Size);
    Table->BucketCount = BucketCount;
    for (i = 0; i < BucketCount; i++) {
        InitializeListHead(&Table->Buckets[i]);
    }
    return Table;
}

static
FORCEINLINE
PLIST_ENTRY
SspsGetPortBucket(
    _In_ PSSPS_HASH_TABLE Table,
    _In_ USHORT Port
    )
{
    return &Table->Buckets[(ULONG)Port & (Table->BucketCount - 1)];
}

static
FORCEINLINE
ULONG
SspsHashAddress(
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
{
    if (IsIPv6) {
        const ULONG *Addr = (const ULONG *)Address;
        return Addr[0] ^ Addr[1] ^ Addr[2] ^ Addr[3];
    }
    return *(const ULONG *)Address;
}

static
FORCEINLINE
PLIST_ENTRY
SspsGetHostBucket(
    _In_ PSSPS_HASH_TABLE Table,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG Hash = SspsHashAddress(Address, IsIPv6);
    return &Table->Buckets[Hash & (Table->BucketCount - 1)];
}

static
FORCEINLINE
BOOLEAN
SspsCompareAddresses(
    _In_ const VOID *Addr1,
    _In_ const VOID *Addr2,
    _In_ BOOLEAN IsIPv6
    )
{
    SIZE_T Len = IsIPv6 ? sizeof(IN6_ADDR) : sizeof(IN_ADDR);
    return RtlCompareMemory(Addr1, Addr2, Len) == Len;
}

//
// Free all entries in a port hash table
//
static
VOID
SspsFreePortHash(
    _In_ PSSPS_HASH_TABLE Table
    )
{
    ULONG i;

    PAGED_CODE();

    if (Table == NULL) return;

    for (i = 0; i < Table->BucketCount; i++) {
        while (!IsListEmpty(&Table->Buckets[i])) {
            PLIST_ENTRY Entry = RemoveHeadList(&Table->Buckets[i]);
            PSSPS_PORT_ENTRY PortEntry = CONTAINING_RECORD(
                Entry, SSPS_PORT_ENTRY, BucketLink);
            ShadowStrikeFreePoolWithTag(PortEntry, SSPS_POOL_TAG_CONTEXT);
        }
    }
    ShadowStrikeFreePoolWithTag(Table, SSPS_POOL_TAG_HASHTBL);
}

//
// Free all entries in a host hash table
//
static
VOID
SspsFreeHostHash(
    _In_ PSSPS_HASH_TABLE Table
    )
{
    ULONG i;

    PAGED_CODE();

    if (Table == NULL) return;

    for (i = 0; i < Table->BucketCount; i++) {
        while (!IsListEmpty(&Table->Buckets[i])) {
            PLIST_ENTRY Entry = RemoveHeadList(&Table->Buckets[i]);
            PSSPS_HOST_ENTRY HostEntry = CONTAINING_RECORD(
                Entry, SSPS_HOST_ENTRY, BucketLink);
            ShadowStrikeFreePoolWithTag(HostEntry, SSPS_POOL_TAG_TARGET);
        }
    }
    ShadowStrikeFreePoolWithTag(Table, SSPS_POOL_TAG_HASHTBL);
}

//
// Free a single source context and all its child allocations.
// Caller must have already removed it from any list.
//
static
VOID
SspsFreeSourceContext(
    _In_ PSSPS_SOURCE_CONTEXT Source
    )
{
    PAGED_CODE();

    // Free connection records
    while (!IsListEmpty(&Source->ConnectionList)) {
        PLIST_ENTRY Entry = RemoveHeadList(&Source->ConnectionList);
        PSSPS_CONNECTION_RECORD Rec = CONTAINING_RECORD(
            Entry, SSPS_CONNECTION_RECORD, ListEntry);
        ShadowStrikeFreePoolWithTag(Rec, SSPS_POOL_TAG_CONTEXT);
    }

    SspsFreePortHash(Source->PortHash);
    SspsFreeHostHash(Source->HostHash);
    ShadowStrikeFreePoolWithTag(Source, SSPS_POOL_TAG_CONTEXT);
}


//=============================================================================
// Detector Active Operation Guard
//=============================================================================
//
// Every public API that touches detector state increments ActiveOperations
// on entry and decrements on exit. Shutdown waits for drain.
//

static
FORCEINLINE
BOOLEAN
SspsAcquireOperation(
    _In_ PSSPS_DETECTOR Detector
    )
{
    if (InterlockedCompareExchange(&Detector->ShuttingDown, 0, 0) != 0) {
        return FALSE;  // Shutting down, reject new operations
    }
    InterlockedIncrement(&Detector->ActiveOperations);
    //
    // Double-check after increment: if shutdown started between the check
    // and the increment, undo and fail.
    //
    if (InterlockedCompareExchange(&Detector->ShuttingDown, 0, 0) != 0) {
        if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
            KeSetEvent(&Detector->DrainEvent, IO_NO_INCREMENT, FALSE);
        }
        return FALSE;
    }
    return TRUE;
}

static
FORCEINLINE
VOID
SspsReleaseOperation(
    _In_ PSSPS_DETECTOR Detector
    )
{
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        KeSetEvent(&Detector->DrainEvent, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// Public API Implementation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SsPsInitialize(
    _Out_ PSSPS_DETECTOR* Detector
    )
/*++
Routine Description:
    Initializes the port scan detection subsystem.
    Must be called at IRQL <= APC_LEVEL.
--*/
{
    PSSPS_DETECTOR Det = NULL;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    Det = (PSSPS_DETECTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(SSPS_DETECTOR), SSPS_POOL_TAG_CONTEXT);
    if (Det == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Det, sizeof(SSPS_DETECTOR));

    InitializeListHead(&Det->SourceList);
    ExInitializePushLock(&Det->SourceListLock);
    KeInitializeEvent(&Det->DrainEvent, NotificationEvent, TRUE);

    Det->Config.WindowMs = SSPS_SCAN_WINDOW_MS;
    Det->Config.MinPortsForScan = SSPS_MIN_PORTS_FOR_SCAN;
    Det->Config.MinHostsForSweep = SSPS_MIN_HOSTS_FOR_SWEEP;

    KeQuerySystemTime(&Det->Stats.StartTime);

    //
    // Register periodic cleanup timer via TimerManager.
    // The callback fires at PASSIVE_LEVEL (TmFlag_WorkItemCallback).
    //
    {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr) {
            TM_TIMER_OPTIONS opts = { 0 };
            opts.Flags = TmFlag_WorkItemCallback | TmFlag_Coalescable;
            opts.ToleranceMs = 5000;
            NTSTATUS tmStatus = TmCreatePeriodic(
                tmMgr,
                SSPS_CLEANUP_INTERVAL_MS,
                SspsCleanupTimerCallback,
                Det,
                &opts,
                &Det->CleanupTimerId);
            if (!NT_SUCCESS(tmStatus)) {
                Det->CleanupTimerId = 0;
            }
        }
    }

    InterlockedExchange(&Det->Initialized, 1);

    *Detector = Det;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SsPsShutdown(
    _Inout_ PSSPS_DETECTOR Detector
    )
/*++
Routine Description:
    Shuts down the port scan detector with proper drain.
    Waits for all in-flight operations to complete before freeing.
    Must be called at IRQL == PASSIVE_LEVEL.
--*/
{
    PLIST_ENTRY Entry;
    PSSPS_SOURCE_CONTEXT Source;
    LARGE_INTEGER Timeout;

    PAGED_CODE();

    if (Detector == NULL ||
        InterlockedCompareExchange(&Detector->Initialized, 0, 0) == 0) {
        return;
    }

    //
    // Phase 1: Signal shutdown â€” reject new operations
    //
    InterlockedExchange(&Detector->ShuttingDown, 1);
    InterlockedExchange(&Detector->Initialized, 0);

    //
    // Phase 2: Cancel TimerManager timer (synchronous â€” waits for in-flight callback)
    //
    if (Detector->CleanupTimerId != 0) {
        PTM_MANAGER tmMgr = ShadowStrikeGetTimerManager();
        if (tmMgr) {
            TmCancel(tmMgr, Detector->CleanupTimerId, TRUE);
        }
        Detector->CleanupTimerId = 0;
    }

    //
    // Phase 3: Wait for all active operations to drain.
    // KeClearEvent BEFORE the check prevents a TOCTOU where the last
    // operation's KeSetEvent fires between the check and KeClearEvent,
    // which would lose the signal and block until timeout.
    //
    KeClearEvent(&Detector->DrainEvent);
    Timeout.QuadPart = -((LONGLONG)SSPS_SHUTDOWN_DRAIN_TIMEOUT_MS * 10000);
    if (InterlockedCompareExchange(&Detector->ActiveOperations, 0, 0) > 0) {
        KeWaitForSingleObject(
            &Detector->DrainEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
            );
    }

    //
    // Phase 4: Free all source contexts (no one can be using them now)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->SourceListLock);

    while (!IsListEmpty(&Detector->SourceList)) {
        Entry = RemoveHeadList(&Detector->SourceList);
        Source = CONTAINING_RECORD(Entry, SSPS_SOURCE_CONTEXT, ListEntry);
        SspsFreeSourceContext(Source);
    }

    ExReleasePushLockExclusive(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    //
    // Phase 5: Free detector
    //
    ShadowStrikeFreePoolWithTag(Detector, SSPS_POOL_TAG_CONTEXT);
}


_Use_decl_annotations_
NTSTATUS
SsPsRecordConnection(
    _In_ PSSPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER ProcessCreateTime,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ UCHAR Protocol,
    _In_ UCHAR TcpFlags,
    _In_ BOOLEAN Successful
    )
/*++
Routine Description:
    Records a connection attempt for port scan detection analysis.
    Validates all inputs. Classifies TCP flags for stealth scan detection.
--*/
{
    PSSPS_SOURCE_CONTEXT Source;
    PSSPS_CONNECTION_RECORD Record;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Detector == NULL || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate protocol
    //
    if (Protocol != 6 && Protocol != 17) {  // IPPROTO_TCP, IPPROTO_UDP
        return STATUS_INVALID_PARAMETER;
    }

    if (!SspsAcquireOperation(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Source = SspsFindOrCreateSource(Detector, ProcessId, ProcessCreateTime);
    if (Source == NULL) {
        SspsReleaseOperation(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeQuerySystemTime(&CurrentTime);

    //
    // Clean up expired records to keep window accurate
    //
    SspsCleanupExpiredRecords(Source, &CurrentTime, Detector->Config.WindowMs);

    //
    // Evict oldest record if at capacity
    //
    if (InterlockedCompareExchange(&Source->ConnectionCount, 0, 0) >=
        SSPS_MAX_CONNECTIONS_PER_SOURCE) {

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Source->ConnectionLock);

        if (!IsListEmpty(&Source->ConnectionList)) {
            PLIST_ENTRY OldEntry = RemoveHeadList(&Source->ConnectionList);
            PSSPS_CONNECTION_RECORD OldRecord = CONTAINING_RECORD(
                OldEntry, SSPS_CONNECTION_RECORD, ListEntry);

            //
            // Capture fields before free to update stats correctly
            //
            BOOLEAN OldSuccessful = OldRecord->Successful;
            UCHAR OldProtocol = OldRecord->Protocol;
            UCHAR OldTcpFlags = OldRecord->TcpFlags;

            ShadowStrikeFreePoolWithTag(OldRecord, SSPS_POOL_TAG_CONTEXT);
            InterlockedDecrement(&Source->ConnectionCount);
            InterlockedDecrement(&Source->WindowStats.TotalConnections);

            if (OldSuccessful) {
                InterlockedDecrement(&Source->WindowStats.SuccessfulConnections);
            } else {
                InterlockedDecrement(&Source->WindowStats.FailedConnections);
            }

            if (OldProtocol == 17) {
                InterlockedDecrement(&Source->WindowStats.UdpConnections);
            }

            if (OldProtocol == 6) {
                SspsReverseClassifyTcpFlags(OldTcpFlags, Source);
            }
        }

        ExReleasePushLockExclusive(&Source->ConnectionLock);
        KeLeaveCriticalRegion();
    }

    //
    // Allocate new connection record
    //
    Record = (PSSPS_CONNECTION_RECORD)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(SSPS_CONNECTION_RECORD), SSPS_POOL_TAG_CONTEXT);
    if (Record == NULL) {
        SspsReleaseSource(Detector, Source);
        SspsReleaseOperation(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Record, sizeof(SSPS_CONNECTION_RECORD));
    Record->RemotePort = RemotePort;
    Record->IsIPv6 = IsIPv6;
    Record->Protocol = Protocol;
    Record->Successful = Successful;
    Record->TcpFlags = TcpFlags;
    Record->Timestamp = CurrentTime;

    if (IsIPv6) {
        RtlCopyMemory(&Record->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&Record->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    //
    // Insert record and update stats under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    InsertTailList(&Source->ConnectionList, &Record->ListEntry);
    InterlockedIncrement(&Source->ConnectionCount);
    InterlockedIncrement(&Source->WindowStats.TotalConnections);

    if (Successful) {
        InterlockedIncrement(&Source->WindowStats.SuccessfulConnections);
    } else {
        InterlockedIncrement(&Source->WindowStats.FailedConnections);
    }

    if (Protocol == 17) {
        InterlockedIncrement(&Source->WindowStats.UdpConnections);
    }

    //
    // Classify TCP flags for stealth scan detection
    //
    if (Protocol == 6) {
        SspsClassifyTcpFlags(TcpFlags, Source);
    }

    //
    // Update timing
    //
    Source->LastActivity = CurrentTime;
    if (Source->FirstActivity.QuadPart == 0) {
        Source->FirstActivity = CurrentTime;
        Source->WindowStart = CurrentTime;
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();

    //
    // Record unique port and host (these acquire ConnectionLock internally)
    //
    SspsRecordUniquePort(Source, RemotePort);
    SspsRecordUniqueHost(Source, RemoteAddress, IsIPv6);

    InterlockedIncrement64(&Detector->Stats.ConnectionsTracked);

    SspsReleaseSource(Detector, Source);
    SspsReleaseOperation(Detector);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
SsPsCheckForScan(
    _In_ PSSPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER ProcessCreateTime,
    _Out_ PSSPS_DETECTION_RESULT* Result
    )
/*++
Routine Description:
    Checks if a process is performing port scanning.
    Allocates a result structure that the caller must free with SsPsFreeResult.
--*/
{
    PLIST_ENTRY Entry;
    PSSPS_SOURCE_CONTEXT Source = NULL;
    PSSPS_DETECTION_RESULT NewResult = NULL;
    LARGE_INTEGER CurrentTime;
    SIZE_T NameLen;

    PAGED_CODE();

    if (Detector == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // Skip excluded processes â€” enterprise policy override.
    //
    if (ShadowStrikeIsProcessExcluded(ProcessId, NULL)) {
        return STATUS_SUCCESS;
    }

    if (!SspsAcquireOperation(Detector)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find source context (shared lock; read-only traversal)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->SourceListLock);

    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = Entry->Flink) {

        PSSPS_SOURCE_CONTEXT Candidate = CONTAINING_RECORD(
            Entry, SSPS_SOURCE_CONTEXT, ListEntry);

        if (Candidate->ProcessId == ProcessId &&
            Candidate->ProcessCreateTime.QuadPart == ProcessCreateTime.QuadPart) {
            Source = Candidate;
            InterlockedIncrement(&Source->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    if (Source == NULL) {
        SspsReleaseOperation(Detector);
        return STATUS_NOT_FOUND;
    }

    KeQuerySystemTime(&CurrentTime);
    SspsCleanupExpiredRecords(Source, &CurrentTime, Detector->Config.WindowMs);

    //
    // Allocate result
    //
    NewResult = (PSSPS_DETECTION_RESULT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(SSPS_DETECTION_RESULT), SSPS_POOL_TAG_CONTEXT);
    if (NewResult == NULL) {
        SspsReleaseSource(Detector, Source);
        SspsReleaseOperation(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewResult, sizeof(SSPS_DETECTION_RESULT));

    //
    // Analyze behavior
    //
    SspsAnalyzeScanBehavior(Source, NewResult);

    NewResult->SourceProcessId = ProcessId;
    NewResult->DetectionTime = CurrentTime;

    //
    // Copy process name into dynamically allocated UNICODE_STRING buffer
    //
    if (Source->ProcessName[0] != L'\0') {
        NameLen = wcslen(Source->ProcessName) * sizeof(WCHAR);
        NewResult->ProcessName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            NameLen + sizeof(WCHAR),
            SSPS_POOL_TAG_CONTEXT);

        if (NewResult->ProcessName.Buffer != NULL) {
            RtlCopyMemory(NewResult->ProcessName.Buffer,
                          Source->ProcessName, NameLen);
            NewResult->ProcessName.Buffer[NameLen / sizeof(WCHAR)] = L'\0';
            NewResult->ProcessName.Length = (USHORT)NameLen;
            NewResult->ProcessName.MaximumLength = (USHORT)(NameLen + sizeof(WCHAR));
        }
    }

    //
    // Update stats on detection
    //
    if (NewResult->ScanDetected) {
        InterlockedIncrement64(&Detector->Stats.ScansDetected);
        Source->ScanDetected = TRUE;
        Source->DetectedScanType = NewResult->Type;
        Source->ConfidenceScore = NewResult->ConfidenceScore;

        //
        // Submit to behavioral engine for attack chain correlation (T1046)
        //
        BeEngineSubmitEvent(
            BehaviorEvent_PortScanning,
            BehaviorCategory_Discovery,
            HandleToULong(ProcessId),
            NULL,
            0,
            (UINT32)NewResult->ConfidenceScore,
            FALSE,
            NULL
            );
    }

    SspsReleaseSource(Detector, Source);
    SspsReleaseOperation(Detector);

    *Result = NewResult;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SsPsGetStatistics(
    _In_ PSSPS_DETECTOR Detector,
    _Out_ PSSPS_STATISTICS Stats
    )
{
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Detector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Detector->Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(SSPS_STATISTICS));

    Stats->TrackedSources = (ULONG)InterlockedCompareExchange(
        &Detector->SourceCount, 0, 0);
    Stats->ConnectionsTracked = (ULONG64)InterlockedCompareExchange64(
        &Detector->Stats.ConnectionsTracked, 0, 0);
    Stats->ScansDetected = (ULONG64)InterlockedCompareExchange64(
        &Detector->Stats.ScansDetected, 0, 0);

    KeQuerySystemTime(&CurrentTime);
    Stats->UpTime.QuadPart = CurrentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SsPsFreeResult(
    _In_ PSSPS_DETECTION_RESULT Result
    )
{
    PAGED_CODE();

    if (Result != NULL) {
        if (Result->ProcessName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(
                Result->ProcessName.Buffer, SSPS_POOL_TAG_CONTEXT);
        }
        ShadowStrikeFreePoolWithTag(Result, SSPS_POOL_TAG_CONTEXT);
    }
}


//=============================================================================
// Internal: Source Context Management
//=============================================================================

static
PSSPS_SOURCE_CONTEXT
SspsFindOrCreateSource(
    _In_ PSSPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER ProcessCreateTime
    )
/*++
Routine Description:
    Finds existing or creates new source context, keyed on (ProcessId, CreateTime)
    to avoid PID-reuse misattribution. Uses double-checked locking pattern.
--*/
{
    PLIST_ENTRY Entry;
    PSSPS_SOURCE_CONTEXT Source = NULL;
    PSSPS_SOURCE_CONTEXT NewSource = NULL;
    BOOLEAN Found = FALSE;

    PAGED_CODE();

    //
    // Phase 1: Shared-lock lookup
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->SourceListLock);

    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = Entry->Flink) {

        Source = CONTAINING_RECORD(Entry, SSPS_SOURCE_CONTEXT, ListEntry);
        if (Source->ProcessId == ProcessId &&
            Source->ProcessCreateTime.QuadPart == ProcessCreateTime.QuadPart) {
            InterlockedIncrement(&Source->RefCount);
            Found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    if (Found) {
        return Source;
    }

    //
    // Check source limit before allocating
    //
    if (InterlockedCompareExchange(&Detector->SourceCount, 0, 0) >=
        SSPS_MAX_TRACKED_SOURCES) {
        return NULL;
    }

    //
    // Allocate new source context
    //
    NewSource = (PSSPS_SOURCE_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(SSPS_SOURCE_CONTEXT), SSPS_POOL_TAG_CONTEXT);
    if (NewSource == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewSource, sizeof(SSPS_SOURCE_CONTEXT));
    NewSource->ProcessId = ProcessId;
    NewSource->ProcessCreateTime = ProcessCreateTime;
    NewSource->RefCount = 1;

    InitializeListHead(&NewSource->ConnectionList);
    ExInitializePushLock(&NewSource->ConnectionLock);

    //
    // Allocate hash tables
    //
    NewSource->PortHash = SspsAllocHashTable(
        SSPS_PORT_HASH_BUCKETS, SSPS_POOL_TAG_HASHTBL);
    NewSource->HostHash = SspsAllocHashTable(
        SSPS_HOST_HASH_BUCKETS, SSPS_POOL_TAG_HASHTBL);

    if (NewSource->PortHash == NULL || NewSource->HostHash == NULL) {
        SspsFreeSourceContext(NewSource);
        return NULL;
    }

    //
    // Get process information (at PASSIVE_LEVEL, safe to call Ps* APIs)
    //
    SspsGetProcessInfo(ProcessId, NewSource->ProcessName,
        ARRAYSIZE(NewSource->ProcessName),
        NewSource->ProcessPath,
        ARRAYSIZE(NewSource->ProcessPath));

    //
    // Phase 2: Exclusive-lock insert with double-check
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->SourceListLock);

    Found = FALSE;
    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = Entry->Flink) {

        Source = CONTAINING_RECORD(Entry, SSPS_SOURCE_CONTEXT, ListEntry);
        if (Source->ProcessId == ProcessId &&
            Source->ProcessCreateTime.QuadPart == ProcessCreateTime.QuadPart) {
            InterlockedIncrement(&Source->RefCount);
            Found = TRUE;
            break;
        }
    }

    if (!Found) {
        InsertTailList(&Detector->SourceList, &NewSource->ListEntry);
        InterlockedIncrement(&Detector->SourceCount);
        Source = NewSource;
        NewSource = NULL;
    }

    ExReleasePushLockExclusive(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    if (NewSource != NULL) {
        SspsFreeSourceContext(NewSource);
    }

    return Source;
}

static
VOID
SspsReleaseSource(
    _In_ PSSPS_DETECTOR Detector,
    _In_ PSSPS_SOURCE_CONTEXT Source
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Detector);

    if (Source != NULL) {
        InterlockedDecrement(&Source->RefCount);
    }
}


//=============================================================================
// Internal: Unique Port / Host Recording (hash-table based)
//=============================================================================

static
VOID
SspsRecordUniquePort(
    _Inout_ PSSPS_SOURCE_CONTEXT Source,
    _In_ USHORT Port
    )
/*++
Routine Description:
    Records a unique port. Uses hash table for O(1) lookup.
    All writes happen under exclusive lock â€” no shared-lock writes.
--*/
{
    PLIST_ENTRY Bucket;
    PLIST_ENTRY Entry;
    PSSPS_PORT_ENTRY PortEntry;
    PSSPS_PORT_ENTRY NewEntry = NULL;
    BOOLEAN Found = FALSE;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    KeQuerySystemTime(&CurrentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    if (Source->PortHash == NULL) {
        ExReleasePushLockExclusive(&Source->ConnectionLock);
        KeLeaveCriticalRegion();
        return;
    }

    Bucket = SspsGetPortBucket(Source->PortHash, Port);

    for (Entry = Bucket->Flink; Entry != Bucket; Entry = Entry->Flink) {
        PortEntry = CONTAINING_RECORD(Entry, SSPS_PORT_ENTRY, BucketLink);
        if (PortEntry->Port == Port) {
            InterlockedIncrement(&PortEntry->HitCount);
            InterlockedExchange64(&PortEntry->LastSeen, CurrentTime.QuadPart);
            Found = TRUE;
            break;
        }
    }

    if (!Found &&
        InterlockedCompareExchange(&Source->UniquePortCount, 0, 0) <
        SSPS_MAX_PORTS_PER_SOURCE) {

        NewEntry = (PSSPS_PORT_ENTRY)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx, sizeof(SSPS_PORT_ENTRY), SSPS_POOL_TAG_CONTEXT);

        if (NewEntry != NULL) {
            RtlZeroMemory(NewEntry, sizeof(SSPS_PORT_ENTRY));
            NewEntry->Port = Port;
            NewEntry->HitCount = 1;
            NewEntry->FirstSeen = CurrentTime;
            InterlockedExchange64(&NewEntry->LastSeen, CurrentTime.QuadPart);
            InsertTailList(Bucket, &NewEntry->BucketLink);
            InterlockedIncrement(&Source->UniquePortCount);
        }
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();
}

static
VOID
SspsRecordUniqueHost(
    _Inout_ PSSPS_SOURCE_CONTEXT Source,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
/*++
Routine Description:
    Records a unique host. Uses hash table for O(1) lookup.
    All writes happen under exclusive lock.
--*/
{
    PLIST_ENTRY Bucket;
    PLIST_ENTRY Entry;
    PSSPS_HOST_ENTRY HostEntry;
    PSSPS_HOST_ENTRY NewEntry = NULL;
    BOOLEAN Found = FALSE;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Address == NULL) {
        return;
    }

    KeQuerySystemTime(&CurrentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    if (Source->HostHash == NULL) {
        ExReleasePushLockExclusive(&Source->ConnectionLock);
        KeLeaveCriticalRegion();
        return;
    }

    Bucket = SspsGetHostBucket(Source->HostHash, Address, IsIPv6);

    for (Entry = Bucket->Flink; Entry != Bucket; Entry = Entry->Flink) {
        HostEntry = CONTAINING_RECORD(Entry, SSPS_HOST_ENTRY, BucketLink);
        if (HostEntry->IsIPv6 == IsIPv6 &&
            SspsCompareAddresses(&HostEntry->Address, Address, IsIPv6)) {
            InterlockedIncrement(&HostEntry->PortsScanned);
            InterlockedExchange64(&HostEntry->LastSeen, CurrentTime.QuadPart);
            Found = TRUE;
            break;
        }
    }

    if (!Found &&
        InterlockedCompareExchange(&Source->UniqueHostCount, 0, 0) <
        SSPS_MAX_HOSTS_PER_SOURCE) {

        NewEntry = (PSSPS_HOST_ENTRY)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx, sizeof(SSPS_HOST_ENTRY), SSPS_POOL_TAG_TARGET);

        if (NewEntry != NULL) {
            RtlZeroMemory(NewEntry, sizeof(SSPS_HOST_ENTRY));
            NewEntry->IsIPv6 = IsIPv6;
            NewEntry->PortsScanned = 1;
            NewEntry->FirstSeen = CurrentTime;
            InterlockedExchange64(&NewEntry->LastSeen, CurrentTime.QuadPart);

            if (IsIPv6) {
                RtlCopyMemory(&NewEntry->Address.IPv6, Address, sizeof(IN6_ADDR));
            } else {
                RtlCopyMemory(&NewEntry->Address.IPv4, Address, sizeof(IN_ADDR));
            }

            InsertTailList(Bucket, &NewEntry->BucketLink);
            InterlockedIncrement(&Source->UniqueHostCount);
        }
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();
}


//=============================================================================
// Internal: Cleanup & Expiry
//=============================================================================

static
VOID
SspsCleanupExpiredRecords(
    _Inout_ PSSPS_SOURCE_CONTEXT Source,
    _In_ PLARGE_INTEGER CurrentTime,
    _In_ ULONG WindowMs
    )
/*++
Routine Description:
    Removes expired connection records, port entries, and host entries
    that fall outside the detection time window.
    Fixes: use-after-free (C-2), port/host expiry (M-1), stats race (M-2).
--*/
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PSSPS_CONNECTION_RECORD Record;
    LONGLONG WindowTicks = (LONGLONG)WindowMs * 10000;
    LONGLONG Cutoff = CurrentTime->QuadPart - WindowTicks;
    ULONG i;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    //
    // Expire connection records
    //
    for (Entry = Source->ConnectionList.Flink;
         Entry != &Source->ConnectionList;
         Entry = NextEntry) {

        NextEntry = Entry->Flink;
        Record = CONTAINING_RECORD(Entry, SSPS_CONNECTION_RECORD, ListEntry);

        if (Record->Timestamp.QuadPart < Cutoff) {
            //
            // Capture fields BEFORE freeing to avoid use-after-free
            //
            BOOLEAN WasSuccessful = Record->Successful;
            UCHAR RecProtocol = Record->Protocol;
            UCHAR RecTcpFlags = Record->TcpFlags;

            RemoveEntryList(Entry);
            ShadowStrikeFreePoolWithTag(Record, SSPS_POOL_TAG_CONTEXT);
            InterlockedDecrement(&Source->ConnectionCount);
            InterlockedDecrement(&Source->WindowStats.TotalConnections);

            if (WasSuccessful) {
                InterlockedDecrement(&Source->WindowStats.SuccessfulConnections);
            } else {
                InterlockedDecrement(&Source->WindowStats.FailedConnections);
            }

            if (RecProtocol == 17) {
                InterlockedDecrement(&Source->WindowStats.UdpConnections);
            }

            if (RecProtocol == 6) {
                SspsReverseClassifyTcpFlags(RecTcpFlags, Source);
            }
        }
    }

    //
    // Expire port entries outside the time window
    //
    if (Source->PortHash != NULL) {
        for (i = 0; i < Source->PortHash->BucketCount; i++) {
            for (Entry = Source->PortHash->Buckets[i].Flink;
                 Entry != &Source->PortHash->Buckets[i];
                 Entry = NextEntry) {

                NextEntry = Entry->Flink;
                PSSPS_PORT_ENTRY PortEntry = CONTAINING_RECORD(
                    Entry, SSPS_PORT_ENTRY, BucketLink);

                LONGLONG PortLastSeen = InterlockedCompareExchange64(
                    &PortEntry->LastSeen, 0, 0);

                if (PortLastSeen < Cutoff) {
                    RemoveEntryList(Entry);
                    ShadowStrikeFreePoolWithTag(PortEntry, SSPS_POOL_TAG_CONTEXT);
                    InterlockedDecrement(&Source->UniquePortCount);
                }
            }
        }
    }

    //
    // Expire host entries outside the time window
    //
    if (Source->HostHash != NULL) {
        for (i = 0; i < Source->HostHash->BucketCount; i++) {
            for (Entry = Source->HostHash->Buckets[i].Flink;
                 Entry != &Source->HostHash->Buckets[i];
                 Entry = NextEntry) {

                NextEntry = Entry->Flink;
                PSSPS_HOST_ENTRY HostEntry = CONTAINING_RECORD(
                    Entry, SSPS_HOST_ENTRY, BucketLink);

                LONGLONG HostLastSeen = InterlockedCompareExchange64(
                    &HostEntry->LastSeen, 0, 0);

                if (HostLastSeen < Cutoff) {
                    RemoveEntryList(Entry);
                    ShadowStrikeFreePoolWithTag(HostEntry, SSPS_POOL_TAG_TARGET);
                    InterlockedDecrement(&Source->UniqueHostCount);
                }
            }
        }
    }

    //
    // Reset window if all connections expired
    //
    if (InterlockedCompareExchange(&Source->ConnectionCount, 0, 0) == 0) {
        Source->WindowStart.QuadPart = 0;
        Source->WindowStats.TotalConnections = 0;
        Source->WindowStats.SuccessfulConnections = 0;
        Source->WindowStats.FailedConnections = 0;
        Source->WindowStats.TcpSynOnly = 0;
        Source->WindowStats.TcpFinOnly = 0;
        Source->WindowStats.TcpXmas = 0;
        Source->WindowStats.TcpNull = 0;
        Source->WindowStats.UdpConnections = 0;
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();
}


//=============================================================================
// Internal: TCP Flag Classification
//=============================================================================

static
VOID
SspsClassifyTcpFlags(
    _In_ UCHAR TcpFlags,
    _Inout_ PSSPS_SOURCE_CONTEXT Source
    )
/*++
Routine Description:
    Classifies TCP flags and increments the appropriate stealth scan counter.
    Must be called while holding Source->ConnectionLock exclusively.
--*/
{
    PAGED_CODE();

    //
    // NULL scan: no flags set
    //
    if (TcpFlags == 0) {
        InterlockedIncrement(&Source->WindowStats.TcpNull);
        return;
    }

    //
    // XMAS scan: FIN + PSH + URG
    //
    if ((TcpFlags & (SSPS_TCP_FLAG_FIN | SSPS_TCP_FLAG_PSH | SSPS_TCP_FLAG_URG)) ==
        (SSPS_TCP_FLAG_FIN | SSPS_TCP_FLAG_PSH | SSPS_TCP_FLAG_URG)) {
        InterlockedIncrement(&Source->WindowStats.TcpXmas);
        return;
    }

    //
    // FIN scan: FIN only, no ACK/SYN/RST
    //
    if (TcpFlags == SSPS_TCP_FLAG_FIN) {
        InterlockedIncrement(&Source->WindowStats.TcpFinOnly);
        return;
    }

    //
    // SYN scan: SYN only, no ACK (half-open)
    //
    if ((TcpFlags & (SSPS_TCP_FLAG_SYN | SSPS_TCP_FLAG_ACK)) == SSPS_TCP_FLAG_SYN) {
        InterlockedIncrement(&Source->WindowStats.TcpSynOnly);
        return;
    }
}

//
// Reverse of SspsClassifyTcpFlags â€” decrements the counter that was
// incremented when the record was inserted.  Called during eviction and
// time-window expiry so that sliding-window TCP-flag ratios stay accurate.
//
static
VOID
SspsReverseClassifyTcpFlags(
    _In_ UCHAR TcpFlags,
    _Inout_ PSSPS_SOURCE_CONTEXT Source
    )
{
    PAGED_CODE();

    if (TcpFlags == 0) {
        InterlockedDecrement(&Source->WindowStats.TcpNull);
        return;
    }

    if ((TcpFlags & (SSPS_TCP_FLAG_FIN | SSPS_TCP_FLAG_PSH | SSPS_TCP_FLAG_URG)) ==
        (SSPS_TCP_FLAG_FIN | SSPS_TCP_FLAG_PSH | SSPS_TCP_FLAG_URG)) {
        InterlockedDecrement(&Source->WindowStats.TcpXmas);
        return;
    }

    if (TcpFlags == SSPS_TCP_FLAG_FIN) {
        InterlockedDecrement(&Source->WindowStats.TcpFinOnly);
        return;
    }

    if ((TcpFlags & (SSPS_TCP_FLAG_SYN | SSPS_TCP_FLAG_ACK)) == SSPS_TCP_FLAG_SYN) {
        InterlockedDecrement(&Source->WindowStats.TcpSynOnly);
        return;
    }
}

//=============================================================================
// Internal: Window Statistics Snapshot
//=============================================================================

static
VOID
SspsSnapshotWindowStats(
    _In_ PSSPS_SOURCE_CONTEXT Source,
    _Out_ PSSPS_WINDOW_SNAPSHOT Snap
    )
/*++
Routine Description:
    Takes an atomic snapshot of all window statistics under the exclusive lock.
    This ensures the aggregate view is consistent (no torn reads between fields).
--*/
{
    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    Snap->TotalConnections      = Source->WindowStats.TotalConnections;
    Snap->SuccessfulConnections = Source->WindowStats.SuccessfulConnections;
    Snap->FailedConnections     = Source->WindowStats.FailedConnections;
    Snap->TcpSynOnly            = Source->WindowStats.TcpSynOnly;
    Snap->TcpFinOnly            = Source->WindowStats.TcpFinOnly;
    Snap->TcpXmas               = Source->WindowStats.TcpXmas;
    Snap->TcpNull               = Source->WindowStats.TcpNull;
    Snap->UdpConnections        = Source->WindowStats.UdpConnections;
    Snap->UniquePortCount       = Source->UniquePortCount;
    Snap->UniqueHostCount       = Source->UniqueHostCount;
    Snap->FirstActivity         = Source->FirstActivity;
    Snap->LastActivity          = Source->LastActivity;

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();
}


//=============================================================================
// Internal: Scan Analysis & Detection
//=============================================================================

static
VOID
SspsAnalyzeScanBehavior(
    _In_ PSSPS_SOURCE_CONTEXT Source,
    _Out_ PSSPS_DETECTION_RESULT Result
    )
/*++
Routine Description:
    Analyzes connection behavior to detect port scanning.
    Takes an atomic snapshot of stats, then analyzes the snapshot.
--*/
{
    SSPS_WINDOW_SNAPSHOT Snap;
    ULONG FailureRate;
    SSPS_SCAN_TYPE ScanType;
    ULONG CommonPortHits = 0;
    ULONG i;

    PAGED_CODE();

    RtlZeroMemory(Result, sizeof(SSPS_DETECTION_RESULT));

    //
    // Take consistent snapshot under lock
    //
    SspsSnapshotWindowStats(Source, &Snap);

    if (Snap.TotalConnections < 5) {
        Result->ScanDetected = FALSE;
        return;
    }

    //
    // Calculate failure rate with bounds checking
    //
    if (Snap.TotalConnections > 0 && Snap.FailedConnections >= 0) {
        LONG ClampedFailed = min(Snap.FailedConnections, Snap.TotalConnections);
        FailureRate = (ULONG)((ClampedFailed * 100) / Snap.TotalConnections);
    } else {
        FailureRate = 0;
    }

    //
    // Calculate duration safely (snapshot is consistent)
    //
    if (Snap.LastActivity.QuadPart > Snap.FirstActivity.QuadPart) {
        LONGLONG DurationTicks = Snap.LastActivity.QuadPart - Snap.FirstActivity.QuadPart;
        Result->DurationMs = (ULONG)(DurationTicks / 10000);
    } else {
        Result->DurationMs = 0;
    }

    Result->UniquePortsScanned = (ULONG)max(Snap.UniquePortCount, 0);
    Result->UniqueHostsScanned = (ULONG)max(Snap.UniqueHostCount, 0);
    Result->ConnectionAttempts = (ULONG)max(Snap.TotalConnections, 0);

    //
    // Determine scan type from TCP flag patterns
    //
    ScanType = SspsDetermineScanType(&Snap);

    //
    // Check for vertical port scan (many ports on few hosts)
    //
    if (Snap.UniquePortCount >= SSPS_VERTICAL_SCAN_THRESHOLD &&
        Snap.UniqueHostCount <= 3) {
        Result->ScanDetected = TRUE;
        Result->Type = (ScanType != SsPsScan_Unknown) ? ScanType : SsPsScan_TCPConnect;
    }
    //
    // Check for horizontal scan / host sweep
    //
    else if (Snap.UniqueHostCount >= SSPS_HORIZONTAL_SCAN_THRESHOLD &&
             Snap.UniquePortCount <= 3) {
        Result->ScanDetected = TRUE;
        Result->Type = SsPsScan_HostSweep;
    }
    //
    // Check for combined scanning (many ports AND many hosts)
    //
    else if (Snap.UniquePortCount >= SSPS_MIN_PORTS_FOR_SCAN / 2 &&
             Snap.UniqueHostCount >= SSPS_MIN_HOSTS_FOR_SWEEP / 2) {
        Result->ScanDetected = TRUE;
        Result->Type = (ScanType != SsPsScan_Unknown) ? ScanType : SsPsScan_TCPConnect;
    }
    //
    // Check for high failure rate with many attempts
    //
    else if (FailureRate >= SSPS_FAILURE_RATE_THRESHOLD &&
             Snap.TotalConnections >= SSPS_RAPID_CONNECT_THRESHOLD) {
        Result->ScanDetected = TRUE;
        Result->Type = SsPsScan_ServiceProbe;
    }
    //
    // Check for stealth scanning techniques
    //
    else if (Snap.TcpSynOnly >= SSPS_STEALTH_SCAN_THRESHOLD ||
             Snap.TcpFinOnly >= SSPS_STEALTH_SCAN_THRESHOLD ||
             Snap.TcpXmas >= SSPS_STEALTH_SCAN_THRESHOLD ||
             Snap.TcpNull >= SSPS_STEALTH_SCAN_THRESHOLD) {
        Result->ScanDetected = TRUE;
        Result->Type = ScanType;
    }

    //
    // Confidence bonus: check if scanned ports match common scanner fingerprint
    //
    if (Result->ScanDetected && Source->PortHash != NULL) {
        CommonPortHits = 0;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Source->ConnectionLock);

        for (i = 0; i < SSPS_COMMON_SCAN_PORTS_COUNT; i++) {
            PLIST_ENTRY Bucket = SspsGetPortBucket(
                Source->PortHash, g_CommonScanPorts[i]);
            PLIST_ENTRY Entry;

            for (Entry = Bucket->Flink; Entry != Bucket; Entry = Entry->Flink) {
                PSSPS_PORT_ENTRY PE = CONTAINING_RECORD(
                    Entry, SSPS_PORT_ENTRY, BucketLink);
                if (PE->Port == g_CommonScanPorts[i]) {
                    CommonPortHits++;
                    break;
                }
            }
        }

        ExReleasePushLockShared(&Source->ConnectionLock);
        KeLeaveCriticalRegion();
    }

    //
    // Calculate confidence score (includes scanner fingerprint bonus)
    //
    if (Result->ScanDetected) {
        Result->ConfidenceScore = SspsCalculateConfidence(&Snap, Result->Type, CommonPortHits);
    }

    //
    // Find primary target (host with most ports scanned)
    //
    if (Result->ScanDetected && Source->HostHash != NULL) {
        PSSPS_HOST_ENTRY PrimaryHost = NULL;
        LONG MaxPorts = 0;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Source->ConnectionLock);

        for (i = 0; i < Source->HostHash->BucketCount; i++) {
            PLIST_ENTRY Entry;
            for (Entry = Source->HostHash->Buckets[i].Flink;
                 Entry != &Source->HostHash->Buckets[i];
                 Entry = Entry->Flink) {

                PSSPS_HOST_ENTRY HE = CONTAINING_RECORD(
                    Entry, SSPS_HOST_ENTRY, BucketLink);
                LONG Ports = InterlockedCompareExchange(&HE->PortsScanned, 0, 0);
                if (Ports > MaxPorts) {
                    MaxPorts = Ports;
                    PrimaryHost = HE;
                }
            }
        }

        if (PrimaryHost != NULL) {
            Result->IsIPv6 = PrimaryHost->IsIPv6;
            if (PrimaryHost->IsIPv6) {
                RtlCopyMemory(&Result->PrimaryTarget.IPv6,
                    &PrimaryHost->Address.IPv6, sizeof(IN6_ADDR));
            } else {
                RtlCopyMemory(&Result->PrimaryTarget.IPv4,
                    &PrimaryHost->Address.IPv4, sizeof(IN_ADDR));
            }
        }

        ExReleasePushLockShared(&Source->ConnectionLock);
        KeLeaveCriticalRegion();
    }
}

static
SSPS_SCAN_TYPE
SspsDetermineScanType(
    _In_ PSSPS_WINDOW_SNAPSHOT Snap
    )
{
    PAGED_CODE();

    if (Snap->TotalConnections == 0) {
        return SsPsScan_Unknown;
    }

    //
    // Check stealth types first (most suspicious).
    // Cast to LONGLONG before multiplication to prevent 32-bit overflow.
    //
    if (Snap->TcpNull > 0 &&
        ((LONGLONG)Snap->TcpNull * 100 / Snap->TotalConnections) > 50) {
        return SsPsScan_TCPNULL;
    }

    if (Snap->TcpXmas > 0 &&
        ((LONGLONG)Snap->TcpXmas * 100 / Snap->TotalConnections) > 50) {
        return SsPsScan_TCPXMAS;
    }

    if (Snap->TcpFinOnly > 0 &&
        ((LONGLONG)Snap->TcpFinOnly * 100 / Snap->TotalConnections) > 50) {
        return SsPsScan_TCPFIN;
    }

    if (Snap->TcpSynOnly > 0 &&
        ((LONGLONG)Snap->TcpSynOnly * 100 / Snap->TotalConnections) > 50) {
        return SsPsScan_TCPSYN;
    }

    if (Snap->UdpConnections > 0 &&
        ((LONGLONG)Snap->UdpConnections * 100 / Snap->TotalConnections) > 80) {
        return SsPsScan_UDPScan;
    }

    return SsPsScan_TCPConnect;
}

static
ULONG
SspsCalculateConfidence(
    _In_ PSSPS_WINDOW_SNAPSHOT Snap,
    _In_ SSPS_SCAN_TYPE ScanType,
    _In_ ULONG CommonPortHits
    )
{
    ULONG Score = 0;
    ULONG FailureRate;

    PAGED_CODE();

    //
    // Unique ports
    //
    if (Snap->UniquePortCount >= SSPS_VERTICAL_SCAN_THRESHOLD * 2) {
        Score += 25 * SSPS_WEIGHT_UNIQUE_PORTS;
    } else if (Snap->UniquePortCount >= SSPS_VERTICAL_SCAN_THRESHOLD) {
        Score += 15 * SSPS_WEIGHT_UNIQUE_PORTS;
    } else if (Snap->UniquePortCount >= (LONG)SSPS_MIN_PORTS_FOR_SCAN) {
        Score += 10 * SSPS_WEIGHT_UNIQUE_PORTS;
    }

    //
    // Unique hosts
    //
    if (Snap->UniqueHostCount >= SSPS_HORIZONTAL_SCAN_THRESHOLD * 2) {
        Score += 25 * SSPS_WEIGHT_UNIQUE_HOSTS;
    } else if (Snap->UniqueHostCount >= SSPS_HORIZONTAL_SCAN_THRESHOLD) {
        Score += 15 * SSPS_WEIGHT_UNIQUE_HOSTS;
    } else if (Snap->UniqueHostCount >= (LONG)SSPS_MIN_HOSTS_FOR_SWEEP) {
        Score += 10 * SSPS_WEIGHT_UNIQUE_HOSTS;
    }

    //
    // Failure rate
    //
    if (Snap->TotalConnections > 0 && Snap->FailedConnections >= 0) {
        LONG Clamped = min(Snap->FailedConnections, Snap->TotalConnections);
        FailureRate = (ULONG)((Clamped * 100) / Snap->TotalConnections);
    } else {
        FailureRate = 0;
    }

    if (FailureRate >= 90) {
        Score += 20 * SSPS_WEIGHT_FAILURE_RATE;
    } else if (FailureRate >= SSPS_FAILURE_RATE_THRESHOLD) {
        Score += 15 * SSPS_WEIGHT_FAILURE_RATE;
    } else if (FailureRate >= 50) {
        Score += 10 * SSPS_WEIGHT_FAILURE_RATE;
    }

    //
    // Scan type weight
    //
    switch (ScanType) {
    case SsPsScan_TCPNULL:
    case SsPsScan_TCPXMAS:
        Score += 30 * SSPS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    case SsPsScan_TCPFIN:
    case SsPsScan_TCPSYN:
        Score += 20 * SSPS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    case SsPsScan_HostSweep:
        Score += 25 * SSPS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    case SsPsScan_UDPScan:
        Score += 15 * SSPS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    default:
        Score += 10 * SSPS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    }

    //
    // Scanner fingerprint bonus: common scan ports matched
    //
    if (CommonPortHits > SSPS_COMMON_SCAN_PORTS_COUNT / 2) {
        Score += 15;
    } else if (CommonPortHits > SSPS_COMMON_SCAN_PORTS_COUNT / 4) {
        Score += 8;
    }

    return min(Score, 100);
}


//=============================================================================
// Internal: Process Information
//=============================================================================

static
VOID
SspsGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize,
    _Out_writes_z_(PathSize) PWCHAR ProcessPath,
    _In_ ULONG PathSize
    )
/*++
Routine Description:
    Gets process name and path. Safe if process has already terminated.
--*/
{
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    PUNICODE_STRING ImageFileName = NULL;

    PAGED_CODE();

    ProcessName[0] = L'\0';
    ProcessPath[0] = L'\0';

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        RtlStringCchCopyW(ProcessName, NameSize, L"<unknown>");
        return;
    }

    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (NT_SUCCESS(Status) && ImageFileName != NULL && ImageFileName->Buffer != NULL) {
        ULONG CharsToPath = min(
            ImageFileName->Length / sizeof(WCHAR),
            PathSize - 1);
        RtlCopyMemory(ProcessPath, ImageFileName->Buffer, CharsToPath * sizeof(WCHAR));
        ProcessPath[CharsToPath] = L'\0';

        PWCHAR LastSlash = wcsrchr(ProcessPath, L'\\');
        if (LastSlash != NULL) {
            RtlStringCchCopyW(ProcessName, NameSize, LastSlash + 1);
        } else {
            RtlStringCchCopyW(ProcessName, NameSize, ProcessPath);
        }

        ExFreePool(ImageFileName);
    } else {
        RtlStringCchCopyW(ProcessName, NameSize, L"<unknown>");
    }

    ObDereferenceObject(Process);
}

//=============================================================================
// Internal: Cleanup Timer Callback (PASSIVE_LEVEL via TimerManager)
//=============================================================================
//
// Architecture:
//   TimerManager fires periodically with TmFlag_WorkItemCallback, so the
//   callback runs at PASSIVE_LEVEL directly.  No DPC-to-work-item trampoline
//   is needed.
//

static
VOID
SspsCleanupTimerCallback(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    TimerManager callback â€” runs at PASSIVE_LEVEL.
    Safely acquires push locks, walks the source list, and removes
    expired source contexts with zero reference count.

    CRITICAL: Participates in the operation drain via SspsAcquireOperation/
    SspsReleaseOperation. This ensures SsPsShutdown waits for this callback
    to complete before freeing the Detector structure.
--*/
{
    PSSPS_DETECTOR Detector = (PSSPS_DETECTOR)Context;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PSSPS_SOURCE_CONTEXT Source;
    LARGE_INTEGER CurrentTime;
    LONGLONG ExpiryTicks = (LONGLONG)SSPS_SOURCE_EXPIRY_MS * 10000;
    LIST_ENTRY ExpiredList;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(TimerId);

    if (Detector == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Detector->ShuttingDown, 0, 0) != 0) {
        return;
    }

    //
    // Prevent overlapping cleanup runs
    //
    if (InterlockedCompareExchange(&Detector->CleanupRunning, 1, 0) != 0) {
        return;  // Previous cleanup still running
    }

    //
    // Acquire operation guard so shutdown drain waits for us.
    // If shutdown is already in progress, exit immediately.
    //
    if (!SspsAcquireOperation(Detector)) {
        InterlockedExchange(&Detector->CleanupRunning, 0);
        return;
    }

    KeQuerySystemTime(&CurrentTime);
    InitializeListHead(&ExpiredList);

    //
    // Collect expired sources under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->SourceListLock);

    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = NextEntry) {

        NextEntry = Entry->Flink;
        Source = CONTAINING_RECORD(Entry, SSPS_SOURCE_CONTEXT, ListEntry);

        //
        // Only expire sources with zero references and sufficient idle time
        //
        if (InterlockedCompareExchange(&Source->RefCount, 0, 0) == 0 &&
            Source->LastActivity.QuadPart > 0 &&
            (CurrentTime.QuadPart - Source->LastActivity.QuadPart) > ExpiryTicks) {

            RemoveEntryList(Entry);
            InterlockedDecrement(&Detector->SourceCount);
            InsertTailList(&ExpiredList, Entry);
        }
    }

    ExReleasePushLockExclusive(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    //
    // Free expired sources outside the lock to minimize lock hold time
    //
    while (!IsListEmpty(&ExpiredList)) {
        Entry = RemoveHeadList(&ExpiredList);
        Source = CONTAINING_RECORD(Entry, SSPS_SOURCE_CONTEXT, ListEntry);
        SspsFreeSourceContext(Source);
    }

    InterlockedExchange(&Detector->CleanupRunning, 0);
    SspsReleaseOperation(Detector);
}
