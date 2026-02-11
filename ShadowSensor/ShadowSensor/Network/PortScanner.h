/*++
    ShadowStrike Next-Generation Antivirus
    Module: PortScanner.h

    Purpose: Port scan detection to identify reconnaissance activity.

    Naming: All public symbols use the SsPs prefix (ShadowStrike Port Scanner)
    to avoid collision with the NT kernel Ps* namespace.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntstrsafe.h>
#include "../../Shared/NetworkTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define SSPS_POOL_TAG_CONTEXT     'CXSP'  // Port Scanner - Context
#define SSPS_POOL_TAG_TARGET      'GTSP'  // Port Scanner - Target
#define SSPS_POOL_TAG_HASHTBL     'HTSP'  // Port Scanner - Hash Table

//=============================================================================
// Configuration
//=============================================================================

#define SSPS_SCAN_WINDOW_MS               60000   // 1 minute
#define SSPS_MIN_PORTS_FOR_SCAN           20      // Unique ports
#define SSPS_MIN_HOSTS_FOR_SWEEP          10      // Unique hosts
#define SSPS_MAX_TRACKED_SOURCES          4096

//=============================================================================
// TCP Flag Constants (for stealth scan classification)
//=============================================================================

#define SSPS_TCP_FLAG_FIN     0x01
#define SSPS_TCP_FLAG_SYN     0x02
#define SSPS_TCP_FLAG_RST     0x04
#define SSPS_TCP_FLAG_PSH     0x08
#define SSPS_TCP_FLAG_ACK     0x10
#define SSPS_TCP_FLAG_URG     0x20

//=============================================================================
// Scan Types
//=============================================================================

typedef enum _SSPS_SCAN_TYPE {
    SsPsScan_Unknown = 0,
    SsPsScan_TCPConnect,
    SsPsScan_TCPSYN,
    SsPsScan_TCPFIN,
    SsPsScan_TCPXMAS,
    SsPsScan_TCPNULL,
    SsPsScan_UDPScan,
    SsPsScan_HostSweep,
    SsPsScan_ServiceProbe,
} SSPS_SCAN_TYPE;

//=============================================================================
// Scan Detection Result
//=============================================================================

typedef struct _SSPS_DETECTION_RESULT {
    BOOLEAN ScanDetected;
    SSPS_SCAN_TYPE Type;
    ULONG ConfidenceScore;

    // Source
    HANDLE SourceProcessId;
    UNICODE_STRING ProcessName;   // Dynamically allocated; freed by SsPsFreeResult

    // Scan metrics
    ULONG UniquePortsScanned;
    ULONG UniqueHostsScanned;
    ULONG ConnectionAttempts;
    ULONG DurationMs;

    // Target information
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } PrimaryTarget;
    BOOLEAN IsIPv6;

    LARGE_INTEGER DetectionTime;

} SSPS_DETECTION_RESULT, *PSSPS_DETECTION_RESULT;

//=============================================================================
// Port Scanner Detector
//=============================================================================

typedef struct _SSPS_DETECTOR {
    volatile LONG Initialized;       // Interlocked flag for safe shutdown
    volatile LONG ShuttingDown;      // Drain flag

    // Source tracking
    LIST_ENTRY SourceList;
    EX_PUSH_LOCK SourceListLock;
    volatile LONG SourceCount;

    // Active reference count for drain
    volatile LONG ActiveOperations;
    KEVENT DrainEvent;               // Signaled when ActiveOperations == 0

    // Cleanup work item (runs at PASSIVE_LEVEL, not DPC)
    PIO_WORKITEM CleanupWorkItem;
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile LONG CleanupRunning;    // Prevents concurrent cleanup runs
    PDEVICE_OBJECT DeviceObject;     // For IoAllocateWorkItem

    // Configuration
    struct {
        ULONG WindowMs;
        ULONG MinPortsForScan;
        ULONG MinHostsForSweep;
    } Config;

    // Statistics
    struct {
        volatile LONG64 ConnectionsTracked;
        volatile LONG64 ScansDetected;
        LARGE_INTEGER StartTime;
    } Stats;

} SSPS_DETECTOR, *PSSPS_DETECTOR;

//=============================================================================
// Public API
//=============================================================================

NTSTATUS
SsPsInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSSPS_DETECTOR* Detector
    );

VOID
SsPsShutdown(
    _Inout_ PSSPS_DETECTOR Detector
    );

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
    );

NTSTATUS
SsPsCheckForScan(
    _In_ PSSPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER ProcessCreateTime,
    _Out_ PSSPS_DETECTION_RESULT* Result
    );

typedef struct _SSPS_STATISTICS {
    ULONG TrackedSources;
    ULONG64 ConnectionsTracked;
    ULONG64 ScansDetected;
    LARGE_INTEGER UpTime;
} SSPS_STATISTICS, *PSSPS_STATISTICS;

NTSTATUS
SsPsGetStatistics(
    _In_ PSSPS_DETECTOR Detector,
    _Out_ PSSPS_STATISTICS Stats
    );

VOID
SsPsFreeResult(
    _In_ PSSPS_DETECTION_RESULT Result
    );

#ifdef __cplusplus
}
#endif
