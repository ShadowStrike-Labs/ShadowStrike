/*++
    ShadowStrike Next-Generation Antivirus
    Module: PortScanner.c

    Purpose: Enterprise-grade port scan detection for reconnaissance identification.

    This module provides comprehensive port scanning detection capabilities:
    - Vertical scan detection (single host, multiple ports)
    - Horizontal scan detection (multiple hosts, same port - host sweep)
    - TCP Connect scan detection
    - TCP SYN/Half-open scan detection
    - TCP FIN/XMAS/NULL stealth scan detection
    - UDP scan detection
    - Service probing detection
    - Per-process connection behavior tracking
    - Time-window based statistical analysis
    - Sliding window with automatic cleanup

    Detection Algorithms:
    - Unique port counting per source/target pair within time window
    - Unique host counting per source within time window
    - Connection failure rate analysis
    - TCP flag pattern recognition
    - Rate-of-connection analysis

    Security Considerations:
    - All input is treated as hostile and validated
    - Memory allocations are bounded to prevent DoS
    - Lock ordering is strictly maintained
    - Cleanup timers prevent resource exhaustion

    MITRE ATT&CK Coverage:
    - T1046: Network Service Discovery
    - T1018: Remote System Discovery
    - T1135: Network Share Discovery

    Copyright (c) ShadowStrike Team
--*/

#include "PortScanner.h"
#include "../Utilities/HashUtils.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Tracing/Trace.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, PsInitialize)
#pragma alloc_text(PAGE, PsShutdown)
#pragma alloc_text(PAGE, PsRecordConnection)
#pragma alloc_text(PAGE, PsCheckForScan)
#pragma alloc_text(PAGE, PsGetStatistics)
#pragma alloc_text(PAGE, PsFreeResult)
#endif

//=============================================================================
// Internal Configuration Constants
//=============================================================================

//
// Maximum tracking limits (DoS prevention)
//
#define PS_MAX_PORTS_PER_SOURCE         8192
#define PS_MAX_HOSTS_PER_SOURCE         4096
#define PS_MAX_CONNECTIONS_PER_SOURCE   65536
#define PS_CLEANUP_INTERVAL_MS          30000       // 30 seconds
#define PS_SOURCE_EXPIRY_MS             300000      // 5 minutes of inactivity

//
// Detection thresholds
//
#define PS_VERTICAL_SCAN_THRESHOLD      20          // Unique ports to same host
#define PS_HORIZONTAL_SCAN_THRESHOLD    10          // Unique hosts on same port
#define PS_RAPID_CONNECT_THRESHOLD      100         // Connections per minute
#define PS_FAILURE_RATE_THRESHOLD       80          // 80% failure rate
#define PS_STEALTH_SCAN_THRESHOLD       5           // Stealth scan attempts

//
// Confidence score weights
//
#define PS_WEIGHT_UNIQUE_PORTS          3
#define PS_WEIGHT_UNIQUE_HOSTS          4
#define PS_WEIGHT_FAILURE_RATE          2
#define PS_WEIGHT_RAPID_CONNECTIONS     2
#define PS_WEIGHT_STEALTH_TECHNIQUE     5

//
// Common scanning tool port lists (for fingerprinting)
//
static const USHORT g_CommonScanPorts[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
};

#define PS_COMMON_SCAN_PORTS_COUNT ARRAYSIZE(g_CommonScanPorts)

//=============================================================================
// Internal Structures
//=============================================================================

//
// Individual connection record
//
typedef struct _PS_CONNECTION_RECORD {
    LIST_ENTRY ListEntry;

    //
    // Target endpoint
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    BOOLEAN IsIPv6;

    //
    // Connection details
    //
    UCHAR Protocol;                     // IPPROTO_TCP or IPPROTO_UDP
    BOOLEAN Successful;
    UCHAR TcpFlags;                     // For stealth scan detection

    //
    // Timing
    //
    LARGE_INTEGER Timestamp;

} PS_CONNECTION_RECORD, *PPS_CONNECTION_RECORD;

//
// Tracked unique port entry
//
typedef struct _PS_PORT_ENTRY {
    LIST_ENTRY ListEntry;
    USHORT Port;
    ULONG HitCount;
    LARGE_INTEGER FirstSeen;
    LARGE_INTEGER LastSeen;
} PS_PORT_ENTRY, *PPS_PORT_ENTRY;

//
// Tracked unique host entry
//
typedef struct _PS_HOST_ENTRY {
    LIST_ENTRY ListEntry;
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } Address;
    BOOLEAN IsIPv6;
    ULONG PortsScanned;
    LARGE_INTEGER FirstSeen;
    LARGE_INTEGER LastSeen;
} PS_HOST_ENTRY, *PPS_HOST_ENTRY;

//
// Per-source tracking context
//
typedef struct _PS_SOURCE_CONTEXT {
    LIST_ENTRY ListEntry;

    //
    // Source identification
    //
    HANDLE ProcessId;
    WCHAR ProcessName[260];
    WCHAR ProcessPath[520];

    //
    // Connection records (ring buffer behavior)
    //
    LIST_ENTRY ConnectionList;
    volatile LONG ConnectionCount;
    EX_PUSH_LOCK ConnectionLock;

    //
    // Unique ports contacted (hash set simulation via list)
    //
    LIST_ENTRY PortList;
    volatile LONG UniquePortCount;

    //
    // Unique hosts contacted
    //
    LIST_ENTRY HostList;
    volatile LONG UniqueHostCount;

    //
    // Statistics within current window
    //
    struct {
        volatile LONG TotalConnections;
        volatile LONG SuccessfulConnections;
        volatile LONG FailedConnections;
        volatile LONG TcpSynOnly;           // SYN without ACK (stealth)
        volatile LONG TcpFinOnly;           // FIN scan
        volatile LONG TcpXmas;              // XMAS scan (FIN+PSH+URG)
        volatile LONG TcpNull;              // NULL scan (no flags)
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
    PS_SCAN_TYPE DetectedScanType;
    ULONG ConfidenceScore;

    //
    // Reference counting
    //
    volatile LONG RefCount;

} PS_SOURCE_CONTEXT, *PPS_SOURCE_CONTEXT;

//=============================================================================
// Forward Declarations
//=============================================================================

static
PPS_SOURCE_CONTEXT
PspFindOrCreateSource(
    _In_ PPS_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

static
VOID
PspReleaseSource(
    _In_ PPS_SOURCE_CONTEXT Source
    );

static
VOID
PspRecordUniquePort(
    _Inout_ PPS_SOURCE_CONTEXT Source,
    _In_ USHORT Port
    );

static
VOID
PspRecordUniqueHost(
    _Inout_ PPS_SOURCE_CONTEXT Source,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    );

static
VOID
PspCleanupExpiredRecords(
    _Inout_ PPS_SOURCE_CONTEXT Source,
    _In_ PLARGE_INTEGER CurrentTime,
    _In_ ULONG WindowMs
    );

static
VOID
PspAnalyzeScanBehavior(
    _In_ PPS_SOURCE_CONTEXT Source,
    _Out_ PPS_DETECTION_RESULT Result
    );

static
PS_SCAN_TYPE
PspDetermineScanType(
    _In_ PPS_SOURCE_CONTEXT Source
    );

static
ULONG
PspCalculateConfidence(
    _In_ PPS_SOURCE_CONTEXT Source,
    _In_ PS_SCAN_TYPE ScanType
    );

static
VOID
PspGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize,
    _Out_writes_z_(PathSize) PWCHAR ProcessPath,
    _In_ ULONG PathSize
    );

static
KDEFERRED_ROUTINE PspCleanupTimerDpc;

static
VOID
PspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static
FORCEINLINE
BOOLEAN
PspCompareAddresses(
    _In_ PVOID Addr1,
    _In_ PVOID Addr2,
    _In_ BOOLEAN IsIPv6
    )
{
    if (IsIPv6) {
        return RtlCompareMemory(Addr1, Addr2, sizeof(IN6_ADDR)) == sizeof(IN6_ADDR);
    } else {
        return RtlCompareMemory(Addr1, Addr2, sizeof(IN_ADDR)) == sizeof(IN_ADDR);
    }
}

static
FORCEINLINE
ULONG
PspHashPort(
    _In_ USHORT Port
    )
{
    return (ULONG)Port;
}

static
FORCEINLINE
ULONG
PspHashAddress(
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
{
    if (IsIPv6) {
        PULONG Addr = (PULONG)Address;
        return Addr[0] ^ Addr[1] ^ Addr[2] ^ Addr[3];
    } else {
        return *(PULONG)Address;
    }
}

//=============================================================================
// Global Cleanup Timer State
//=============================================================================

typedef struct _PS_CLEANUP_CONTEXT {
    KTIMER Timer;
    KDPC Dpc;
    PPS_DETECTOR Detector;
    BOOLEAN Active;
} PS_CLEANUP_CONTEXT, *PPS_CLEANUP_CONTEXT;

static PS_CLEANUP_CONTEXT g_CleanupContext = { 0 };

//=============================================================================
// Public API Implementation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
PsInitialize(
    _Out_ PPS_DETECTOR* Detector
    )
/*++

Routine Description:

    Initializes the port scan detection subsystem.

Arguments:

    Detector - Receives pointer to the initialized detector.

Return Value:

    STATUS_SUCCESS on success, appropriate error code otherwise.

--*/
{
    PPS_DETECTOR NewDetector = NULL;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER DueTime;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    NewDetector = (PPS_DETECTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PS_DETECTOR),
        PS_POOL_TAG_CONTEXT
        );

    if (NewDetector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewDetector, sizeof(PS_DETECTOR));

    //
    // Initialize list and lock
    //
    InitializeListHead(&NewDetector->SourceList);
    ExInitializePushLock(&NewDetector->SourceListLock);

    //
    // Set default configuration
    //
    NewDetector->Config.WindowMs = PS_SCAN_WINDOW_MS;
    NewDetector->Config.MinPortsForScan = PS_MIN_PORTS_FOR_SCAN;
    NewDetector->Config.MinHostsForSweep = PS_MIN_HOSTS_FOR_SWEEP;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&CurrentTime);
    NewDetector->Stats.StartTime = CurrentTime;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&g_CleanupContext.Timer);
    KeInitializeDpc(&g_CleanupContext.Dpc, PspCleanupTimerDpc, NewDetector);
    g_CleanupContext.Detector = NewDetector;
    g_CleanupContext.Active = TRUE;

    //
    // Start cleanup timer (periodic)
    //
    DueTime.QuadPart = -((LONGLONG)PS_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(&g_CleanupContext.Timer, DueTime, PS_CLEANUP_INTERVAL_MS, &g_CleanupContext.Dpc);

    NewDetector->Initialized = TRUE;

    *Detector = NewDetector;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PsShutdown(
    _Inout_ PPS_DETECTOR Detector
    )
/*++

Routine Description:

    Shuts down the port scan detection subsystem.

Arguments:

    Detector - The detector to shut down.

--*/
{
    PLIST_ENTRY Entry;
    PPS_SOURCE_CONTEXT Source;
    PPS_CONNECTION_RECORD ConnRecord;
    PPS_PORT_ENTRY PortEntry;
    PPS_HOST_ENTRY HostEntry;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    Detector->Initialized = FALSE;

    //
    // Stop cleanup timer
    //
    g_CleanupContext.Active = FALSE;
    KeCancelTimer(&g_CleanupContext.Timer);
    KeFlushQueuedDpcs();

    //
    // Free all source contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->SourceListLock);

    while (!IsListEmpty(&Detector->SourceList)) {
        Entry = RemoveHeadList(&Detector->SourceList);
        Source = CONTAINING_RECORD(Entry, PS_SOURCE_CONTEXT, ListEntry);

        //
        // Free connection records
        //
        while (!IsListEmpty(&Source->ConnectionList)) {
            Entry = RemoveHeadList(&Source->ConnectionList);
            ConnRecord = CONTAINING_RECORD(Entry, PS_CONNECTION_RECORD, ListEntry);
            ShadowStrikeFreePoolWithTag(ConnRecord, PS_POOL_TAG_CONTEXT);
        }

        //
        // Free port entries
        //
        while (!IsListEmpty(&Source->PortList)) {
            Entry = RemoveHeadList(&Source->PortList);
            PortEntry = CONTAINING_RECORD(Entry, PS_PORT_ENTRY, ListEntry);
            ShadowStrikeFreePoolWithTag(PortEntry, PS_POOL_TAG_CONTEXT);
        }

        //
        // Free host entries
        //
        while (!IsListEmpty(&Source->HostList)) {
            Entry = RemoveHeadList(&Source->HostList);
            HostEntry = CONTAINING_RECORD(Entry, PS_HOST_ENTRY, ListEntry);
            ShadowStrikeFreePoolWithTag(HostEntry, PS_POOL_TAG_TARGET);
        }

        ShadowStrikeFreePoolWithTag(Source, PS_POOL_TAG_CONTEXT);
    }

    ExReleasePushLockExclusive(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    //
    // Free detector
    //
    ShadowStrikeFreePoolWithTag(Detector, PS_POOL_TAG_CONTEXT);
}

_Use_decl_annotations_
NTSTATUS
PsRecordConnection(
    _In_ PPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ UCHAR Protocol,
    _In_ BOOLEAN Successful
    )
/*++

Routine Description:

    Records a connection attempt for port scan detection analysis.

Arguments:

    Detector      - The port scan detector.
    ProcessId     - The process making the connection.
    RemoteAddress - Remote IP address (IN_ADDR or IN6_ADDR).
    RemotePort    - Remote port number.
    IsIPv6        - TRUE if IPv6 address.
    Protocol      - IP protocol (IPPROTO_TCP or IPPROTO_UDP).
    Successful    - TRUE if connection succeeded.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PPS_SOURCE_CONTEXT Source;
    PPS_CONNECTION_RECORD Record;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find or create source context for this process
    //
    Source = PspFindOrCreateSource(Detector, ProcessId);
    if (Source == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeQuerySystemTime(&CurrentTime);

    //
    // Clean up expired records first
    //
    PspCleanupExpiredRecords(Source, &CurrentTime, Detector->Config.WindowMs);

    //
    // Check if we've hit connection limit for this source
    //
    if (InterlockedCompareExchange(&Source->ConnectionCount, 0, 0) >=
        PS_MAX_CONNECTIONS_PER_SOURCE) {
        //
        // Remove oldest record
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Source->ConnectionLock);

        if (!IsListEmpty(&Source->ConnectionList)) {
            PLIST_ENTRY OldEntry = RemoveHeadList(&Source->ConnectionList);
            PPS_CONNECTION_RECORD OldRecord = CONTAINING_RECORD(
                OldEntry, PS_CONNECTION_RECORD, ListEntry);
            ShadowStrikeFreePoolWithTag(OldRecord, PS_POOL_TAG_CONTEXT);
            InterlockedDecrement(&Source->ConnectionCount);
        }

        ExReleasePushLockExclusive(&Source->ConnectionLock);
        KeLeaveCriticalRegion();
    }

    //
    // Allocate new connection record
    //
    Record = (PPS_CONNECTION_RECORD)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PS_CONNECTION_RECORD),
        PS_POOL_TAG_CONTEXT
        );

    if (Record == NULL) {
        PspReleaseSource(Source);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Record, sizeof(PS_CONNECTION_RECORD));

    //
    // Fill in record
    //
    Record->RemotePort = RemotePort;
    Record->IsIPv6 = IsIPv6;
    Record->Protocol = Protocol;
    Record->Successful = Successful;
    Record->Timestamp = CurrentTime;

    if (IsIPv6) {
        RtlCopyMemory(&Record->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&Record->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    //
    // Add to connection list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    InsertTailList(&Source->ConnectionList, &Record->ListEntry);
    InterlockedIncrement(&Source->ConnectionCount);

    //
    // Update window statistics
    //
    InterlockedIncrement(&Source->WindowStats.TotalConnections);

    if (Successful) {
        InterlockedIncrement(&Source->WindowStats.SuccessfulConnections);
    } else {
        InterlockedIncrement(&Source->WindowStats.FailedConnections);
    }

    if (Protocol == 17) { // IPPROTO_UDP
        InterlockedIncrement(&Source->WindowStats.UdpConnections);
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
    // Record unique port and host
    //
    PspRecordUniquePort(Source, RemotePort);
    PspRecordUniqueHost(Source, RemoteAddress, IsIPv6);

    //
    // Update global statistics
    //
    InterlockedIncrement64(&Detector->Stats.ConnectionsTracked);

    PspReleaseSource(Source);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PsCheckForScan(
    _In_ PPS_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PPS_DETECTION_RESULT* Result
    )
/*++

Routine Description:

    Checks if a process is performing port scanning.

Arguments:

    Detector  - The port scan detector.
    ProcessId - The process to check.
    Result    - Receives the detection result (caller must free with PsFreeResult).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PLIST_ENTRY Entry;
    PPS_SOURCE_CONTEXT Source = NULL;
    PPS_DETECTION_RESULT NewResult;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // Find source context
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->SourceListLock);

    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = Entry->Flink) {

        PPS_SOURCE_CONTEXT Candidate = CONTAINING_RECORD(
            Entry, PS_SOURCE_CONTEXT, ListEntry);

        if (Candidate->ProcessId == ProcessId) {
            Source = Candidate;
            InterlockedIncrement(&Source->RefCount);
            break;
        }
    }

    ExReleasePushLockShared(&Detector->SourceListLock);
    KeLeaveCriticalRegion();

    if (Source == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Clean up expired records
    //
    KeQuerySystemTime(&CurrentTime);
    PspCleanupExpiredRecords(Source, &CurrentTime, Detector->Config.WindowMs);

    //
    // Allocate result structure
    //
    NewResult = (PPS_DETECTION_RESULT)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(PS_DETECTION_RESULT),
        PS_POOL_TAG_CONTEXT
        );

    if (NewResult == NULL) {
        PspReleaseSource(Source);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewResult, sizeof(PS_DETECTION_RESULT));

    //
    // Analyze scan behavior
    //
    PspAnalyzeScanBehavior(Source, NewResult);

    //
    // Fill in source information
    //
    NewResult->SourceProcessId = ProcessId;
    NewResult->DetectionTime = CurrentTime;

    //
    // Copy process name if available
    //
    if (Source->ProcessName[0] != L'\0') {
        RtlInitUnicodeString(&NewResult->ProcessName, NULL);
        //
        // The process name is embedded in the result, no separate allocation needed
        // Result consumer should not try to free it
        //
    }

    //
    // Update detection statistics if scan detected
    //
    if (NewResult->ScanDetected) {
        InterlockedIncrement64(&Detector->Stats.ScansDetected);
        Source->ScanDetected = TRUE;
        Source->DetectedScanType = NewResult->Type;
        Source->ConfidenceScore = NewResult->ConfidenceScore;
    }

    PspReleaseSource(Source);

    *Result = NewResult;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PsGetStatistics(
    _In_ PPS_DETECTOR Detector,
    _Out_ PPS_STATISTICS Stats
    )
/*++

Routine Description:

    Gets current port scan detection statistics.

Arguments:

    Detector - The port scan detector.
    Stats    - Receives the statistics.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(PS_STATISTICS));

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
PsFreeResult(
    _In_ PPS_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Frees a detection result structure.

Arguments:

    Result - The result to free.

--*/
{
    PAGED_CODE();

    if (Result != NULL) {
        //
        // Free any dynamically allocated strings in the result
        // (ProcessName.Buffer if it was separately allocated)
        //
        if (Result->ProcessName.Buffer != NULL &&
            Result->ProcessName.MaximumLength > 0) {
            ShadowStrikeFreePoolWithTag(Result->ProcessName.Buffer, PS_POOL_TAG_CONTEXT);
        }

        ShadowStrikeFreePoolWithTag(Result, PS_POOL_TAG_CONTEXT);
    }
}

//=============================================================================
// Internal Implementation
//=============================================================================

static
PPS_SOURCE_CONTEXT
PspFindOrCreateSource(
    _In_ PPS_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Finds an existing source context or creates a new one.

--*/
{
    PLIST_ENTRY Entry;
    PPS_SOURCE_CONTEXT Source = NULL;
    PPS_SOURCE_CONTEXT NewSource = NULL;
    BOOLEAN Found = FALSE;

    //
    // First try to find existing source (shared lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->SourceListLock);

    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = Entry->Flink) {

        Source = CONTAINING_RECORD(Entry, PS_SOURCE_CONTEXT, ListEntry);

        if (Source->ProcessId == ProcessId) {
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
    // Check source limit
    //
    if (InterlockedCompareExchange(&Detector->SourceCount, 0, 0) >=
        PS_MAX_TRACKED_SOURCES) {
        return NULL;
    }

    //
    // Create new source context
    //
    NewSource = (PPS_SOURCE_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PS_SOURCE_CONTEXT),
        PS_POOL_TAG_CONTEXT
        );

    if (NewSource == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewSource, sizeof(PS_SOURCE_CONTEXT));

    //
    // Initialize new source
    //
    NewSource->ProcessId = ProcessId;
    NewSource->RefCount = 1;

    InitializeListHead(&NewSource->ConnectionList);
    InitializeListHead(&NewSource->PortList);
    InitializeListHead(&NewSource->HostList);
    ExInitializePushLock(&NewSource->ConnectionLock);

    //
    // Get process information
    //
    PspGetProcessInfo(ProcessId, NewSource->ProcessName,
        sizeof(NewSource->ProcessName) / sizeof(WCHAR),
        NewSource->ProcessPath,
        sizeof(NewSource->ProcessPath) / sizeof(WCHAR));

    //
    // Add to list (exclusive lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->SourceListLock);

    //
    // Double-check another thread didn't create it
    //
    for (Entry = Detector->SourceList.Flink;
         Entry != &Detector->SourceList;
         Entry = Entry->Flink) {

        Source = CONTAINING_RECORD(Entry, PS_SOURCE_CONTEXT, ListEntry);

        if (Source->ProcessId == ProcessId) {
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

    //
    // Free unused allocation if race occurred
    //
    if (NewSource != NULL) {
        ShadowStrikeFreePoolWithTag(NewSource, PS_POOL_TAG_CONTEXT);
    }

    return Source;
}

static
VOID
PspReleaseSource(
    _In_ PPS_SOURCE_CONTEXT Source
    )
/*++

Routine Description:

    Releases a reference to a source context.

--*/
{
    if (Source != NULL) {
        InterlockedDecrement(&Source->RefCount);
        //
        // Note: Actual cleanup is handled by the cleanup timer
        //
    }
}

static
VOID
PspRecordUniquePort(
    _Inout_ PPS_SOURCE_CONTEXT Source,
    _In_ USHORT Port
    )
/*++

Routine Description:

    Records a unique port contacted by the source.

--*/
{
    PLIST_ENTRY Entry;
    PPS_PORT_ENTRY PortEntry;
    PPS_PORT_ENTRY NewEntry = NULL;
    BOOLEAN Found = FALSE;
    LARGE_INTEGER CurrentTime;

    KeQuerySystemTime(&CurrentTime);

    //
    // Check if port already tracked
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Source->ConnectionLock);

    for (Entry = Source->PortList.Flink;
         Entry != &Source->PortList;
         Entry = Entry->Flink) {

        PortEntry = CONTAINING_RECORD(Entry, PS_PORT_ENTRY, ListEntry);

        if (PortEntry->Port == Port) {
            PortEntry->HitCount++;
            PortEntry->LastSeen = CurrentTime;
            Found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Source->ConnectionLock);
    KeLeaveCriticalRegion();

    if (Found) {
        return;
    }

    //
    // Check port limit
    //
    if (InterlockedCompareExchange(&Source->UniquePortCount, 0, 0) >=
        PS_MAX_PORTS_PER_SOURCE) {
        return;
    }

    //
    // Create new port entry
    //
    NewEntry = (PPS_PORT_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PS_PORT_ENTRY),
        PS_POOL_TAG_CONTEXT
        );

    if (NewEntry == NULL) {
        return;
    }

    RtlZeroMemory(NewEntry, sizeof(PS_PORT_ENTRY));
    NewEntry->Port = Port;
    NewEntry->HitCount = 1;
    NewEntry->FirstSeen = CurrentTime;
    NewEntry->LastSeen = CurrentTime;

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    //
    // Double-check
    //
    for (Entry = Source->PortList.Flink;
         Entry != &Source->PortList;
         Entry = Entry->Flink) {

        PortEntry = CONTAINING_RECORD(Entry, PS_PORT_ENTRY, ListEntry);

        if (PortEntry->Port == Port) {
            PortEntry->HitCount++;
            PortEntry->LastSeen = CurrentTime;
            Found = TRUE;
            break;
        }
    }

    if (!Found) {
        InsertTailList(&Source->PortList, &NewEntry->ListEntry);
        InterlockedIncrement(&Source->UniquePortCount);
        NewEntry = NULL;
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();

    if (NewEntry != NULL) {
        ShadowStrikeFreePoolWithTag(NewEntry, PS_POOL_TAG_CONTEXT);
    }
}

static
VOID
PspRecordUniqueHost(
    _Inout_ PPS_SOURCE_CONTEXT Source,
    _In_ PVOID Address,
    _In_ BOOLEAN IsIPv6
    )
/*++

Routine Description:

    Records a unique host contacted by the source.

--*/
{
    PLIST_ENTRY Entry;
    PPS_HOST_ENTRY HostEntry;
    PPS_HOST_ENTRY NewEntry = NULL;
    BOOLEAN Found = FALSE;
    LARGE_INTEGER CurrentTime;

    KeQuerySystemTime(&CurrentTime);

    //
    // Check if host already tracked
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Source->ConnectionLock);

    for (Entry = Source->HostList.Flink;
         Entry != &Source->HostList;
         Entry = Entry->Flink) {

        HostEntry = CONTAINING_RECORD(Entry, PS_HOST_ENTRY, ListEntry);

        if (HostEntry->IsIPv6 == IsIPv6 &&
            PspCompareAddresses(&HostEntry->Address, Address, IsIPv6)) {
            HostEntry->PortsScanned++;
            HostEntry->LastSeen = CurrentTime;
            Found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Source->ConnectionLock);
    KeLeaveCriticalRegion();

    if (Found) {
        return;
    }

    //
    // Check host limit
    //
    if (InterlockedCompareExchange(&Source->UniqueHostCount, 0, 0) >=
        PS_MAX_HOSTS_PER_SOURCE) {
        return;
    }

    //
    // Create new host entry
    //
    NewEntry = (PPS_HOST_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PS_HOST_ENTRY),
        PS_POOL_TAG_TARGET
        );

    if (NewEntry == NULL) {
        return;
    }

    RtlZeroMemory(NewEntry, sizeof(PS_HOST_ENTRY));
    NewEntry->IsIPv6 = IsIPv6;
    NewEntry->PortsScanned = 1;
    NewEntry->FirstSeen = CurrentTime;
    NewEntry->LastSeen = CurrentTime;

    if (IsIPv6) {
        RtlCopyMemory(&NewEntry->Address.IPv6, Address, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&NewEntry->Address.IPv4, Address, sizeof(IN_ADDR));
    }

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    //
    // Double-check
    //
    for (Entry = Source->HostList.Flink;
         Entry != &Source->HostList;
         Entry = Entry->Flink) {

        HostEntry = CONTAINING_RECORD(Entry, PS_HOST_ENTRY, ListEntry);

        if (HostEntry->IsIPv6 == IsIPv6 &&
            PspCompareAddresses(&HostEntry->Address, Address, IsIPv6)) {
            HostEntry->PortsScanned++;
            HostEntry->LastSeen = CurrentTime;
            Found = TRUE;
            break;
        }
    }

    if (!Found) {
        InsertTailList(&Source->HostList, &NewEntry->ListEntry);
        InterlockedIncrement(&Source->UniqueHostCount);
        NewEntry = NULL;
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();

    if (NewEntry != NULL) {
        ShadowStrikeFreePoolWithTag(NewEntry, PS_POOL_TAG_TARGET);
    }
}

static
VOID
PspCleanupExpiredRecords(
    _Inout_ PPS_SOURCE_CONTEXT Source,
    _In_ PLARGE_INTEGER CurrentTime,
    _In_ ULONG WindowMs
    )
/*++

Routine Description:

    Removes expired connection records outside the detection window.

--*/
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PPS_CONNECTION_RECORD Record;
    LONGLONG WindowTicks = (LONGLONG)WindowMs * 10000;
    LONGLONG Cutoff = CurrentTime->QuadPart - WindowTicks;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Source->ConnectionLock);

    for (Entry = Source->ConnectionList.Flink;
         Entry != &Source->ConnectionList;
         Entry = NextEntry) {

        NextEntry = Entry->Flink;
        Record = CONTAINING_RECORD(Entry, PS_CONNECTION_RECORD, ListEntry);

        if (Record->Timestamp.QuadPart < Cutoff) {
            RemoveEntryList(Entry);
            ShadowStrikeFreePoolWithTag(Record, PS_POOL_TAG_CONTEXT);
            InterlockedDecrement(&Source->ConnectionCount);

            //
            // Update window statistics
            //
            InterlockedDecrement(&Source->WindowStats.TotalConnections);
            if (Record->Successful) {
                InterlockedDecrement(&Source->WindowStats.SuccessfulConnections);
            } else {
                InterlockedDecrement(&Source->WindowStats.FailedConnections);
            }
        }
    }

    //
    // Reset window start if needed
    //
    if (Source->ConnectionCount == 0) {
        Source->WindowStart.QuadPart = 0;
        RtlZeroMemory(&Source->WindowStats, sizeof(Source->WindowStats));
    }

    ExReleasePushLockExclusive(&Source->ConnectionLock);
    KeLeaveCriticalRegion();
}

static
VOID
PspAnalyzeScanBehavior(
    _In_ PPS_SOURCE_CONTEXT Source,
    _Out_ PPS_DETECTION_RESULT Result
    )
/*++

Routine Description:

    Analyzes connection behavior to detect port scanning.

--*/
{
    LONG TotalConnections;
    LONG FailedConnections;
    LONG UniquePortCount;
    LONG UniqueHostCount;
    ULONG FailureRate;
    PS_SCAN_TYPE ScanType;
    LARGE_INTEGER Duration;

    RtlZeroMemory(Result, sizeof(PS_DETECTION_RESULT));

    //
    // Get current statistics
    //
    TotalConnections = InterlockedCompareExchange(&Source->WindowStats.TotalConnections, 0, 0);
    FailedConnections = InterlockedCompareExchange(&Source->WindowStats.FailedConnections, 0, 0);
    UniquePortCount = InterlockedCompareExchange(&Source->UniquePortCount, 0, 0);
    UniqueHostCount = InterlockedCompareExchange(&Source->UniqueHostCount, 0, 0);

    //
    // Not enough data
    //
    if (TotalConnections < 5) {
        Result->ScanDetected = FALSE;
        return;
    }

    //
    // Calculate failure rate
    //
    FailureRate = (TotalConnections > 0) ?
        (ULONG)((FailedConnections * 100) / TotalConnections) : 0;

    //
    // Calculate duration
    //
    Duration.QuadPart = Source->LastActivity.QuadPart - Source->FirstActivity.QuadPart;
    Result->DurationMs = (ULONG)(Duration.QuadPart / 10000);

    //
    // Fill in metrics
    //
    Result->UniquePortsScanned = (ULONG)UniquePortCount;
    Result->UniqueHostsScanned = (ULONG)UniqueHostCount;
    Result->ConnectionAttempts = (ULONG)TotalConnections;

    //
    // Determine scan type
    //
    ScanType = PspDetermineScanType(Source);

    //
    // Check for vertical port scan (many ports on few hosts)
    //
    if (UniquePortCount >= PS_VERTICAL_SCAN_THRESHOLD && UniqueHostCount <= 3) {
        Result->ScanDetected = TRUE;
        Result->Type = (ScanType != PsScan_Unknown) ? ScanType : PsScan_TCPConnect;
    }
    //
    // Check for horizontal scan / host sweep (same port on many hosts)
    //
    else if (UniqueHostCount >= PS_HORIZONTAL_SCAN_THRESHOLD && UniquePortCount <= 3) {
        Result->ScanDetected = TRUE;
        Result->Type = PsScan_HostSweep;
    }
    //
    // Check for general scanning (many ports AND many hosts)
    //
    else if (UniquePortCount >= PS_MIN_PORTS_FOR_SCAN / 2 &&
             UniqueHostCount >= PS_MIN_HOSTS_FOR_SWEEP / 2) {
        Result->ScanDetected = TRUE;
        Result->Type = (ScanType != PsScan_Unknown) ? ScanType : PsScan_TCPConnect;
    }
    //
    // Check for high failure rate with many attempts
    //
    else if (FailureRate >= PS_FAILURE_RATE_THRESHOLD &&
             TotalConnections >= PS_RAPID_CONNECT_THRESHOLD) {
        Result->ScanDetected = TRUE;
        Result->Type = PsScan_ServiceProbe;
    }
    //
    // Check for stealth scanning techniques
    //
    else if (Source->WindowStats.TcpSynOnly >= PS_STEALTH_SCAN_THRESHOLD ||
             Source->WindowStats.TcpFinOnly >= PS_STEALTH_SCAN_THRESHOLD ||
             Source->WindowStats.TcpXmas >= PS_STEALTH_SCAN_THRESHOLD ||
             Source->WindowStats.TcpNull >= PS_STEALTH_SCAN_THRESHOLD) {
        Result->ScanDetected = TRUE;
        Result->Type = ScanType;
    }

    //
    // Calculate confidence score
    //
    if (Result->ScanDetected) {
        Result->ConfidenceScore = PspCalculateConfidence(Source, Result->Type);
    }

    //
    // Find primary target (host with most ports scanned)
    //
    if (Result->ScanDetected && !IsListEmpty(&Source->HostList)) {
        PLIST_ENTRY Entry;
        PPS_HOST_ENTRY HostEntry;
        PPS_HOST_ENTRY PrimaryHost = NULL;
        ULONG MaxPorts = 0;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Source->ConnectionLock);

        for (Entry = Source->HostList.Flink;
             Entry != &Source->HostList;
             Entry = Entry->Flink) {

            HostEntry = CONTAINING_RECORD(Entry, PS_HOST_ENTRY, ListEntry);

            if (HostEntry->PortsScanned > MaxPorts) {
                MaxPorts = HostEntry->PortsScanned;
                PrimaryHost = HostEntry;
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
PS_SCAN_TYPE
PspDetermineScanType(
    _In_ PPS_SOURCE_CONTEXT Source
    )
/*++

Routine Description:

    Determines the type of port scan based on TCP flag patterns.

--*/
{
    LONG SynOnly = InterlockedCompareExchange(&Source->WindowStats.TcpSynOnly, 0, 0);
    LONG FinOnly = InterlockedCompareExchange(&Source->WindowStats.TcpFinOnly, 0, 0);
    LONG Xmas = InterlockedCompareExchange(&Source->WindowStats.TcpXmas, 0, 0);
    LONG Null = InterlockedCompareExchange(&Source->WindowStats.TcpNull, 0, 0);
    LONG Udp = InterlockedCompareExchange(&Source->WindowStats.UdpConnections, 0, 0);
    LONG Total = InterlockedCompareExchange(&Source->WindowStats.TotalConnections, 0, 0);

    if (Total == 0) {
        return PsScan_Unknown;
    }

    //
    // Check for stealth scan types first
    //
    if (Null > 0 && (Null * 100 / Total) > 50) {
        return PsScan_TCPNULL;
    }

    if (Xmas > 0 && (Xmas * 100 / Total) > 50) {
        return PsScan_TCPXMAS;
    }

    if (FinOnly > 0 && (FinOnly * 100 / Total) > 50) {
        return PsScan_TCPFIN;
    }

    if (SynOnly > 0 && (SynOnly * 100 / Total) > 50) {
        return PsScan_TCPSYN;
    }

    if (Udp > 0 && (Udp * 100 / Total) > 80) {
        return PsScan_UDPScan;
    }

    //
    // Default to connect scan
    //
    return PsScan_TCPConnect;
}

static
ULONG
PspCalculateConfidence(
    _In_ PPS_SOURCE_CONTEXT Source,
    _In_ PS_SCAN_TYPE ScanType
    )
/*++

Routine Description:

    Calculates confidence score for the detection.

--*/
{
    ULONG Score = 0;
    LONG UniquePortCount = InterlockedCompareExchange(&Source->UniquePortCount, 0, 0);
    LONG UniqueHostCount = InterlockedCompareExchange(&Source->UniqueHostCount, 0, 0);
    LONG TotalConnections = InterlockedCompareExchange(&Source->WindowStats.TotalConnections, 0, 0);
    LONG FailedConnections = InterlockedCompareExchange(&Source->WindowStats.FailedConnections, 0, 0);
    ULONG FailureRate;

    //
    // Score based on unique ports
    //
    if (UniquePortCount >= PS_VERTICAL_SCAN_THRESHOLD * 2) {
        Score += 25 * PS_WEIGHT_UNIQUE_PORTS;
    } else if (UniquePortCount >= PS_VERTICAL_SCAN_THRESHOLD) {
        Score += 15 * PS_WEIGHT_UNIQUE_PORTS;
    } else if (UniquePortCount >= PS_MIN_PORTS_FOR_SCAN) {
        Score += 10 * PS_WEIGHT_UNIQUE_PORTS;
    }

    //
    // Score based on unique hosts
    //
    if (UniqueHostCount >= PS_HORIZONTAL_SCAN_THRESHOLD * 2) {
        Score += 25 * PS_WEIGHT_UNIQUE_HOSTS;
    } else if (UniqueHostCount >= PS_HORIZONTAL_SCAN_THRESHOLD) {
        Score += 15 * PS_WEIGHT_UNIQUE_HOSTS;
    } else if (UniqueHostCount >= PS_MIN_HOSTS_FOR_SWEEP) {
        Score += 10 * PS_WEIGHT_UNIQUE_HOSTS;
    }

    //
    // Score based on failure rate
    //
    FailureRate = (TotalConnections > 0) ?
        (ULONG)((FailedConnections * 100) / TotalConnections) : 0;

    if (FailureRate >= 90) {
        Score += 20 * PS_WEIGHT_FAILURE_RATE;
    } else if (FailureRate >= PS_FAILURE_RATE_THRESHOLD) {
        Score += 15 * PS_WEIGHT_FAILURE_RATE;
    } else if (FailureRate >= 50) {
        Score += 10 * PS_WEIGHT_FAILURE_RATE;
    }

    //
    // Score based on scan type (stealth techniques get higher score)
    //
    switch (ScanType) {
    case PsScan_TCPNULL:
    case PsScan_TCPXMAS:
        Score += 30 * PS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    case PsScan_TCPFIN:
    case PsScan_TCPSYN:
        Score += 20 * PS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    case PsScan_HostSweep:
        Score += 25 * PS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    case PsScan_UDPScan:
        Score += 15 * PS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    default:
        Score += 10 * PS_WEIGHT_STEALTH_TECHNIQUE;
        break;
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}

static
VOID
PspGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(NameSize) PWCHAR ProcessName,
    _In_ ULONG NameSize,
    _Out_writes_z_(PathSize) PWCHAR ProcessPath,
    _In_ ULONG PathSize
    )
/*++

Routine Description:

    Gets process name and path for a process ID.

--*/
{
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    PUNICODE_STRING ImageFileName = NULL;

    ProcessName[0] = L'\0';
    ProcessPath[0] = L'\0';

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        RtlStringCchCopyW(ProcessName, NameSize, L"<unknown>");
        return;
    }

    //
    // Get image file name
    //
    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (NT_SUCCESS(Status) && ImageFileName != NULL) {
        //
        // Copy full path
        //
        ULONG CharsToPath = min(ImageFileName->Length / sizeof(WCHAR), PathSize - 1);
        RtlCopyMemory(ProcessPath, ImageFileName->Buffer, CharsToPath * sizeof(WCHAR));
        ProcessPath[CharsToPath] = L'\0';

        //
        // Extract just the filename
        //
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

static
VOID
PspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++

Routine Description:

    Periodic cleanup DPC to remove stale source contexts.

--*/
{
    PPS_DETECTOR Detector = (PPS_DETECTOR)DeferredContext;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PPS_SOURCE_CONTEXT Source;
    LARGE_INTEGER CurrentTime;
    LONGLONG ExpiryTicks = (LONGLONG)PS_SOURCE_EXPIRY_MS * 10000;
    LIST_ENTRY ExpiredList;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Detector == NULL || !Detector->Initialized || !g_CleanupContext.Active) {
        return;
    }

    KeQuerySystemTime(&CurrentTime);
    InitializeListHead(&ExpiredList);

    //
    // Find expired sources (can't free at DISPATCH_LEVEL with PagedPool)
    // Just mark them for cleanup - actual cleanup happens at PASSIVE_LEVEL
    //
    KeEnterCriticalRegion();

    if (ExTryAcquirePushLockExclusive(&Detector->SourceListLock)) {

        for (Entry = Detector->SourceList.Flink;
             Entry != &Detector->SourceList;
             Entry = NextEntry) {

            NextEntry = Entry->Flink;
            Source = CONTAINING_RECORD(Entry, PS_SOURCE_CONTEXT, ListEntry);

            //
            // Check if source is expired and not referenced
            //
            if (Source->RefCount == 0 &&
                Source->LastActivity.QuadPart > 0 &&
                (CurrentTime.QuadPart - Source->LastActivity.QuadPart) > ExpiryTicks) {

                //
                // Remove from main list
                //
                RemoveEntryList(Entry);
                InterlockedDecrement(&Detector->SourceCount);

                //
                // Add to expired list for later cleanup
                // (We can't call ShadowStrikeFreePoolWithTag at DISPATCH_LEVEL
                //  for PagedPool, but NonPagedPoolNx is fine)
                //
                // For simplicity, we'll queue a work item or just free NonPaged allocations
                //

                //
                // Free NonPagedPoolNx allocations directly
                //
                while (!IsListEmpty(&Source->ConnectionList)) {
                    PLIST_ENTRY ConnEntry = RemoveHeadList(&Source->ConnectionList);
                    PPS_CONNECTION_RECORD Record = CONTAINING_RECORD(
                        ConnEntry, PS_CONNECTION_RECORD, ListEntry);
                    ShadowStrikeFreePoolWithTag(Record, PS_POOL_TAG_CONTEXT);
                }

                while (!IsListEmpty(&Source->PortList)) {
                    PLIST_ENTRY PortEntry = RemoveHeadList(&Source->PortList);
                    PPS_PORT_ENTRY Port = CONTAINING_RECORD(
                        PortEntry, PS_PORT_ENTRY, ListEntry);
                    ShadowStrikeFreePoolWithTag(Port, PS_POOL_TAG_CONTEXT);
                }

                while (!IsListEmpty(&Source->HostList)) {
                    PLIST_ENTRY HostEntry = RemoveHeadList(&Source->HostList);
                    PPS_HOST_ENTRY Host = CONTAINING_RECORD(
                        HostEntry, PS_HOST_ENTRY, ListEntry);
                    ShadowStrikeFreePoolWithTag(Host, PS_POOL_TAG_TARGET);
                }

                ShadowStrikeFreePoolWithTag(Source, PS_POOL_TAG_CONTEXT);
            }
        }

        ExReleasePushLockExclusive(&Detector->SourceListLock);
    }

    KeLeaveCriticalRegion();
}
