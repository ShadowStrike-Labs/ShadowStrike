/*++
    ShadowStrike Next-Generation Antivirus
    Module: PortScanner.h
    
    Purpose: Port scan detection to identify reconnaissance activity.
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/NetworkTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define PS_POOL_TAG_CONTEXT     'CXSP'  // Port Scanner - Context
#define PS_POOL_TAG_TARGET      'GTSP'  // Port Scanner - Target

//=============================================================================
// Configuration
//=============================================================================

#define PS_SCAN_WINDOW_MS               60000   // 1 minute
#define PS_MIN_PORTS_FOR_SCAN           20      // Unique ports
#define PS_MIN_HOSTS_FOR_SWEEP          10      // Unique hosts
#define PS_MAX_TRACKED_SOURCES          4096

//=============================================================================
// Scan Types
//=============================================================================

typedef enum _PS_SCAN_TYPE {
    PsScan_Unknown = 0,
    PsScan_TCPConnect,
    PsScan_TCPSYN,
    PsScan_TCPFIN,
    PsScan_TCPXMAS,
    PsScan_TCPNULL,
    PsScan_UDPScan,
    PsScan_HostSweep,
    PsScan_ServiceProbe,
} PS_SCAN_TYPE;

//=============================================================================
// Scan Detection Result
//=============================================================================

typedef struct _PS_DETECTION_RESULT {
    BOOLEAN ScanDetected;
    PS_SCAN_TYPE Type;
    ULONG ConfidenceScore;
    
    // Source
    HANDLE SourceProcessId;
    UNICODE_STRING ProcessName;
    
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
    
} PS_DETECTION_RESULT, *PPS_DETECTION_RESULT;

//=============================================================================
// Port Scanner Detector
//=============================================================================

typedef struct _PS_DETECTOR {
    BOOLEAN Initialized;
    
    // Source tracking
    LIST_ENTRY SourceList;
    EX_PUSH_LOCK SourceListLock;
    volatile LONG SourceCount;
    
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
    
} PS_DETECTOR, *PPS_DETECTOR;

//=============================================================================
// Public API
//=============================================================================

NTSTATUS
PsInitialize(
    _Out_ PPS_DETECTOR* Detector
    );

VOID
PsShutdown(
    _Inout_ PPS_DETECTOR Detector
    );

NTSTATUS
PsRecordConnection(
    _In_ PPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ UCHAR Protocol,
    _In_ BOOLEAN Successful
    );

NTSTATUS
PsCheckForScan(
    _In_ PPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PPS_DETECTION_RESULT* Result
    );

typedef struct _PS_STATISTICS {
    ULONG TrackedSources;
    ULONG64 ConnectionsTracked;
    ULONG64 ScansDetected;
    LARGE_INTEGER UpTime;
} PS_STATISTICS, *PPS_STATISTICS;

NTSTATUS
PsGetStatistics(
    _In_ PPS_DETECTOR Detector,
    _Out_ PPS_STATISTICS Stats
    );

VOID
PsFreeResult(
    _In_ PPS_DETECTION_RESULT Result
    );

#ifdef __cplusplus
}
#endif
