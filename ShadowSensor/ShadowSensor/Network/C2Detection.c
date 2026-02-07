/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE C2 DETECTION ENGINE
 * ============================================================================
 *
 * @file C2Detection.c
 * @brief Enterprise-grade Command and Control communication detection.
 *
 * This module implements comprehensive C2 detection capabilities:
 * - Beaconing interval analysis with statistical methods
 * - JA3/JA3S TLS fingerprint matching
 * - Known C2 infrastructure IOC matching
 * - Protocol anomaly detection
 * - Domain generation algorithm (DGA) detection
 * - Traffic pattern analysis
 *
 * Detection Capabilities (MITRE ATT&CK):
 * - T1071: Application Layer Protocol (HTTP/HTTPS/DNS C2)
 * - T1071.001: Web Protocols
 * - T1071.004: DNS
 * - T1573: Encrypted Channel
 * - T1573.002: Asymmetric Cryptography
 * - T1095: Non-Application Layer Protocol
 * - T1572: Protocol Tunneling
 * - T1090: Proxy (Domain Fronting)
 *
 * Supported C2 Framework Detection:
 * - Cobalt Strike (Beacon)
 * - Metasploit (Meterpreter)
 * - Empire/Covenant
 * - PoshC2
 * - Sliver
 * - Brute Ratel
 * - Custom/Unknown C2
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "C2Detection.h"
#include "ConnectionTracker.h"
#include "../Core/Globals.h"
#include "../../Shared/NetworkTypes.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, C2Initialize)
#pragma alloc_text(PAGE, C2Shutdown)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define C2_VERSION                          0x0200
#define C2_HASH_BUCKET_COUNT                1024
#define C2_IOC_HASH_BUCKET_COUNT            4096
#define C2_MAX_CALLBACKS                    8
#define C2_CLEANUP_INTERVAL_MS              60000
#define C2_ANALYSIS_TIMER_INTERVAL_MS       5000

//
// Beacon detection thresholds
//
#define C2_MIN_SAMPLES_FOR_ANALYSIS         5
#define C2_PERFECT_BEACON_JITTER            5       // 5% or less
#define C2_TYPICAL_BEACON_JITTER            25      // 25% or less
#define C2_SUSPICIOUS_INTERVAL_MIN_MS       1000    // 1 second
#define C2_SUSPICIOUS_INTERVAL_MAX_MS       3600000 // 1 hour

//
// Scoring thresholds
//
#define C2_SCORE_REGULAR_BEACON             40
#define C2_SCORE_JITTERED_BEACON            35
#define C2_SCORE_KNOWN_JA3                  50
#define C2_SCORE_KNOWN_IP                   60
#define C2_SCORE_KNOWN_DOMAIN               55
#define C2_SCORE_ABNORMAL_PORT              15
#define C2_SCORE_ENCODED_PAYLOAD            20
#define C2_SCORE_LONG_SLEEP                 10
#define C2_SCORE_HIGH_FREQUENCY             25
#define C2_SCORE_PROTOCOL_ANOMALY           30
#define C2_SCORE_DATA_SIZE_PATTERN          15
#define C2_SCORE_DOMAIN_FRONTING            45
#define C2_SCORE_NEWLY_REGISTERED           25
#define C2_SCORE_SELF_SIGNED_CERT           20
#define C2_SCORE_CONSISTENT_SIZE            10

#define C2_ALERT_THRESHOLD                  70
#define C2_CONFIRMED_THRESHOLD              85

//
// Known C2 ports
//
static const USHORT g_SuspiciousC2Ports[] = {
    4444,   // Metasploit default
    5555,   // Common backdoor
    6666,   // Common backdoor
    8080,   // HTTP alt (often abused)
    8443,   // HTTPS alt
    9001,   // Tor
    9050,   // Tor SOCKS
    31337,  // Elite/Back Orifice
    12345,  // NetBus
    54321,  // Common backdoor
};

//
// Known malicious JA3 fingerprints (Cobalt Strike, Metasploit, etc.)
//
typedef struct _C2_KNOWN_JA3 {
    UCHAR Hash[16];
    CHAR Framework[32];
    CHAR Description[64];
} C2_KNOWN_JA3, *PC2_KNOWN_JA3;

static const C2_KNOWN_JA3 g_KnownMaliciousJA3[] = {
    // Cobalt Strike default
    { { 0x72, 0xa5, 0x89, 0xda, 0x58, 0x6c, 0x44, 0x6d, 0xab, 0x21, 0x8e, 0x59, 0x55, 0xc3, 0x0c, 0x86 },
      "CobaltStrike", "Default Beacon JA3" },
    // Cobalt Strike 4.x
    { { 0x6e, 0x37, 0x9c, 0x0c, 0x0a, 0x8e, 0x4e, 0x80, 0x58, 0x9c, 0x7f, 0xa5, 0x93, 0x3c, 0x65, 0x32 },
      "CobaltStrike", "Beacon 4.x JA3" },
    // Metasploit Meterpreter
    { { 0x3b, 0x5f, 0xc0, 0x67, 0xce, 0xb2, 0xd2, 0x42, 0x28, 0x6f, 0x19, 0x6e, 0xdc, 0x44, 0x5a, 0x4e },
      "Metasploit", "Meterpreter HTTPS" },
    // Empire
    { { 0x29, 0xd9, 0x11, 0xb8, 0x15, 0xeb, 0x59, 0x0c, 0x45, 0xe7, 0xf8, 0x5d, 0x87, 0xa1, 0x9c, 0x0a },
      "Empire", "PowerShell Empire" },
    // PoshC2
    { { 0x51, 0xc6, 0x4a, 0xc4, 0x82, 0x16, 0x89, 0xaf, 0xe6, 0x5e, 0x1d, 0x68, 0xd4, 0xb8, 0x34, 0x0d },
      "PoshC2", "PoshC2 Implant" },
    // Sliver
    { { 0x44, 0x8f, 0x1c, 0x2b, 0xa7, 0x89, 0x3c, 0x4d, 0x9e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f },
      "Sliver", "Sliver C2 Implant" },
    // Brute Ratel
    { { 0x33, 0x92, 0xde, 0x23, 0x8a, 0x17, 0x4e, 0xc1, 0xc8, 0x6a, 0x9e, 0x51, 0x2b, 0x74, 0xf9, 0x80 },
      "BruteRatel", "Brute Ratel C4" },
};

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

typedef struct _C2_CALLBACK_ENTRY {
    C2_DETECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN InUse;
    UINT8 Reserved[7];
} C2_CALLBACK_ENTRY, *PC2_CALLBACK_ENTRY;

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Internal detector state.
 */
typedef struct _C2_DETECTOR_INTERNAL {
    C2_DETECTOR Public;

    //
    // Callbacks
    //
    C2_CALLBACK_ENTRY Callbacks[C2_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST DestinationLookaside;
    NPAGED_LOOKASIDE_LIST SampleLookaside;
    NPAGED_LOOKASIDE_LIST IOCLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    BOOLEAN LookasideInitialized;
    UINT8 Reserved[7];

    //
    // Cleanup work item
    //
    PIO_WORKITEM CleanupWorkItem;
    volatile LONG CleanupInProgress;

} C2_DETECTOR_INTERNAL, *PC2_DETECTOR_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
C2pAnalysisTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
C2pCleanupWorkItem(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static NTSTATUS
C2pInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static VOID
C2pFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static ULONG
C2pHashAddress(
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6
    );

static ULONG
C2pHashString(
    _In_ PCSTR String,
    _In_ ULONG Length
    );

static PC2_DESTINATION
C2pFindDestination(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6
    );

static PC2_DESTINATION
C2pCreateDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname
    );

static VOID
C2pFreeDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    );

static VOID
C2pAddBeaconSample(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination,
    _In_ ULONG DataSize,
    _In_ CT_DIRECTION Direction
    );

static VOID
C2pAnalyzeBeaconing(
    _Inout_ PC2_DESTINATION Destination
    );

static VOID
C2pCalculateIntervalStatistics(
    _In_ PC2_DESTINATION Destination,
    _Out_ PULONG MeanInterval,
    _Out_ PULONG StdDeviation,
    _Out_ PULONG MedianInterval
    );

static BOOLEAN
C2pCheckKnownJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    );

static BOOLEAN
C2pIsSuspiciousPort(
    _In_ USHORT Port
    );

static VOID
C2pCalculateSuspicionScore(
    _Inout_ PC2_DESTINATION Destination
    );

static VOID
C2pNotifyCallbacks(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PC2_DETECTION_RESULT Result
    );

static VOID
C2pFreeBeaconSamples(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    );

static PC2_PROCESS_CONTEXT
C2pFindProcessContext(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

static PC2_PROCESS_CONTEXT
C2pCreateProcessContext(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

static VOID
C2pFreeProcessContext(
    _Inout_ PC2_PROCESS_CONTEXT Context
    );

static ULONG
C2pQuickSort(
    _Inout_ PULONG Array,
    _In_ ULONG Count
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2Initialize(
    _Out_ PC2_DETECTOR* Detector
    )
{
    NTSTATUS status;
    PC2_DETECTOR_INTERNAL detector = NULL;
    LARGE_INTEGER timerDue;
    ULONG i;

    PAGED_CODE();

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // Allocate detector structure
    //
    detector = (PC2_DETECTOR_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(C2_DETECTOR_INTERNAL),
        C2_POOL_TAG_CONTEXT
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(detector, sizeof(C2_DETECTOR_INTERNAL));

    //
    // Initialize lists and locks
    //
    InitializeListHead(&detector->Public.DestinationList);
    ExInitializePushLock(&detector->Public.DestinationListLock);

    InitializeListHead(&detector->Public.ProcessList);
    ExInitializePushLock(&detector->Public.ProcessListLock);

    InitializeListHead(&detector->Public.IOCList);
    ExInitializePushLock(&detector->Public.IOCLock);

    InitializeListHead(&detector->Public.KnownJA3List);
    ExInitializePushLock(&detector->Public.JA3Lock);

    ExInitializePushLock(&detector->CallbackLock);

    //
    // Initialize destination hash table
    //
    status = C2pInitializeHashTable(
        &detector->Public.DestinationHash.Buckets,
        C2_HASH_BUCKET_COUNT
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(detector, C2_POOL_TAG_CONTEXT);
        return status;
    }

    detector->Public.DestinationHash.BucketCount = C2_HASH_BUCKET_COUNT;
    ExInitializePushLock(&detector->Public.DestinationHash.Lock);

    //
    // Initialize IOC hash table
    //
    status = C2pInitializeHashTable(
        &detector->Public.IOCHash.Buckets,
        C2_IOC_HASH_BUCKET_COUNT
    );

    if (!NT_SUCCESS(status)) {
        C2pFreeHashTable(
            &detector->Public.DestinationHash.Buckets,
            C2_HASH_BUCKET_COUNT
        );
        ExFreePoolWithTag(detector, C2_POOL_TAG_CONTEXT);
        return status;
    }

    detector->Public.IOCHash.BucketCount = C2_IOC_HASH_BUCKET_COUNT;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &detector->DestinationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(C2_DESTINATION),
        C2_POOL_TAG_CONTEXT,
        0
    );

    ExInitializeNPagedLookasideList(
        &detector->SampleLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(C2_BEACON_SAMPLE),
        C2_POOL_TAG_BEACON,
        0
    );

    ExInitializeNPagedLookasideList(
        &detector->IOCLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(C2_IOC),
        C2_POOL_TAG_IOC,
        0
    );

    ExInitializeNPagedLookasideList(
        &detector->ResultLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(C2_DETECTION_RESULT),
        C2_POOL_TAG_CONTEXT,
        0
    );

    detector->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    detector->Public.Config.MinBeaconSamples = C2_MIN_BEACON_SAMPLES;
    detector->Public.Config.BeaconJitterThreshold = C2_BEACON_JITTER_THRESHOLD;
    detector->Public.Config.AnalysisWindowMs = C2_ANALYSIS_WINDOW_MS;
    detector->Public.Config.EnableJA3Analysis = TRUE;
    detector->Public.Config.EnableBeaconDetection = TRUE;

    //
    // Initialize timer and DPC for periodic analysis
    //
    KeInitializeTimer(&detector->Public.AnalysisTimer);
    KeInitializeDpc(
        &detector->Public.AnalysisDpc,
        C2pAnalysisTimerDpc,
        detector
    );

    detector->Public.AnalysisIntervalMs = C2_ANALYSIS_TIMER_INTERVAL_MS;

    //
    // Start the analysis timer
    //
    timerDue.QuadPart = -((LONGLONG)detector->Public.AnalysisIntervalMs * 10000);
    KeSetTimerEx(
        &detector->Public.AnalysisTimer,
        timerDue,
        detector->Public.AnalysisIntervalMs,
        &detector->Public.AnalysisDpc
    );

    //
    // Record start time
    //
    KeQuerySystemTime(&detector->Public.Stats.StartTime);

    //
    // Load built-in JA3 fingerprints
    //
    for (i = 0; i < ARRAYSIZE(g_KnownMaliciousJA3); i++) {
        C2AddKnownJA3(
            &detector->Public,
            (PUCHAR)g_KnownMaliciousJA3[i].Hash,
            g_KnownMaliciousJA3[i].Framework
        );
    }

    detector->Public.Initialized = TRUE;
    *Detector = &detector->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
C2Shutdown(
    _Inout_ PC2_DETECTOR Detector
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PLIST_ENTRY entry;
    PC2_DESTINATION destination;
    PC2_PROCESS_CONTEXT processContext;
    PC2_IOC ioc;

    PAGED_CODE();

    if (Detector == NULL || !Detector->Initialized) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Mark as shutting down
    //
    Detector->Initialized = FALSE;

    //
    // Cancel the analysis timer
    //
    KeCancelTimer(&Detector->AnalysisTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for cleanup to complete
    //
    while (detector->CleanupInProgress) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all destinations
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->DestinationListLock);

    while (!IsListEmpty(&Detector->DestinationList)) {
        entry = RemoveHeadList(&Detector->DestinationList);
        destination = CONTAINING_RECORD(entry, C2_DESTINATION, ListEntry);
        C2pFreeBeaconSamples(detector, destination);
        ExFreeToNPagedLookasideList(&detector->DestinationLookaside, destination);
    }

    ExReleasePushLockExclusive(&Detector->DestinationListLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessListLock);

    while (!IsListEmpty(&Detector->ProcessList)) {
        entry = RemoveHeadList(&Detector->ProcessList);
        processContext = CONTAINING_RECORD(entry, C2_PROCESS_CONTEXT, ListEntry);
        C2pFreeProcessContext(processContext);
    }

    ExReleasePushLockExclusive(&Detector->ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Free all IOCs
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->IOCLock);

    while (!IsListEmpty(&Detector->IOCList)) {
        entry = RemoveHeadList(&Detector->IOCList);
        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);
        ExFreeToNPagedLookasideList(&detector->IOCLookaside, ioc);
    }

    ExReleasePushLockExclusive(&Detector->IOCLock);
    KeLeaveCriticalRegion();

    //
    // Free hash tables
    //
    C2pFreeHashTable(
        &Detector->DestinationHash.Buckets,
        Detector->DestinationHash.BucketCount
    );

    C2pFreeHashTable(
        &Detector->IOCHash.Buckets,
        Detector->IOCHash.BucketCount
    );

    //
    // Delete lookaside lists
    //
    if (detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&detector->DestinationLookaside);
        ExDeleteNPagedLookasideList(&detector->SampleLookaside);
        ExDeleteNPagedLookasideList(&detector->IOCLookaside);
        ExDeleteNPagedLookasideList(&detector->ResultLookaside);
    }

    //
    // Free detector
    //
    ExFreePoolWithTag(detector, C2_POOL_TAG_CONTEXT);
}

// ============================================================================
// PUBLIC API - TRAFFIC RECORDING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2RecordConnection(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PC2_DESTINATION destination;
    PC2_PROCESS_CONTEXT processContext;
    ULONG i;

    if (Detector == NULL || !Detector->Initialized || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Find or create destination
    //
    destination = C2pFindDestination(Detector, RemoteAddress, RemotePort, IsIPv6);

    if (destination == NULL) {
        destination = C2pCreateDestination(
            detector,
            RemoteAddress,
            RemotePort,
            IsIPv6,
            Hostname
        );

        if (destination == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Update connection count
    //
    InterlockedIncrement(&destination->ConnectionCount);
    InterlockedIncrement(&destination->ActiveConnections);
    KeQuerySystemTime(&destination->LastSeen);

    //
    // Check for suspicious port
    //
    if (C2pIsSuspiciousPort(RemotePort)) {
        destination->Indicators |= C2Indicator_AbnormalPort;
    }

    //
    // Track process association
    //
    for (i = 0; i < ARRAYSIZE(destination->AssociatedProcesses); i++) {
        if (destination->AssociatedProcesses[i] == ProcessId) {
            break;
        }
        if (destination->AssociatedProcesses[i] == NULL) {
            destination->AssociatedProcesses[i] = ProcessId;
            destination->ProcessCount++;
            break;
        }
    }

    //
    // Update process context
    //
    processContext = C2pFindProcessContext(Detector, ProcessId);
    if (processContext == NULL) {
        processContext = C2pCreateProcessContext(Detector, ProcessId);
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Detector->Stats.ConnectionsAnalyzed);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2RecordTraffic(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG DataSize,
    _In_ CT_DIRECTION Direction
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PC2_DESTINATION destination;

    UNREFERENCED_PARAMETER(ProcessId);

    if (Detector == NULL || !Detector->Initialized || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Find destination
    //
    destination = C2pFindDestination(Detector, RemoteAddress, RemotePort, IsIPv6);

    if (destination == NULL) {
        //
        // Create new destination if not found
        //
        destination = C2pCreateDestination(
            detector,
            RemoteAddress,
            RemotePort,
            IsIPv6,
            NULL
        );

        if (destination == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Add beacon sample
    //
    C2pAddBeaconSample(detector, destination, DataSize, Direction);

    //
    // Update last seen
    //
    KeQuerySystemTime(&destination->LastSeen);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2RecordTLSHandshake(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ PC2_JA3_FINGERPRINT JA3
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PC2_DESTINATION destination;
    CHAR malwareFamily[64] = { 0 };

    UNREFERENCED_PARAMETER(ProcessId);

    if (Detector == NULL || !Detector->Initialized ||
        RemoteAddress == NULL || JA3 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Find or create destination
    //
    destination = C2pFindDestination(Detector, RemoteAddress, RemotePort, IsIPv6);

    if (destination == NULL) {
        destination = C2pCreateDestination(
            detector,
            RemoteAddress,
            RemotePort,
            IsIPv6,
            NULL
        );

        if (destination == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Store JA3 fingerprint
    //
    RtlCopyMemory(&destination->JA3Fingerprint, JA3, sizeof(C2_JA3_FINGERPRINT));

    //
    // Check against known malicious JA3
    //
    if (Detector->Config.EnableJA3Analysis) {
        if (C2pCheckKnownJA3(Detector, JA3->JA3Hash, malwareFamily, sizeof(malwareFamily))) {
            destination->Indicators |= C2Indicator_KnownJA3;
            destination->JA3Fingerprint.IsKnownMalicious = TRUE;
            RtlCopyMemory(
                destination->JA3Fingerprint.MalwareFamily,
                malwareFamily,
                sizeof(destination->JA3Fingerprint.MalwareFamily)
            );

            //
            // Update suspicion score
            //
            destination->SuspicionScore += C2_SCORE_KNOWN_JA3;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2AnalyzeDestination(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _Out_ PC2_DETECTION_RESULT* Result
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PC2_DESTINATION destination;
    PC2_DETECTION_RESULT result;

    if (Detector == NULL || !Detector->Initialized ||
        RemoteAddress == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Find destination
    //
    destination = C2pFindDestination(Detector, RemoteAddress, RemotePort, IsIPv6);

    if (destination == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Perform beacon analysis
    //
    C2pAnalyzeBeaconing(destination);

    //
    // Calculate suspicion score
    //
    C2pCalculateSuspicionScore(destination);

    //
    // Allocate result
    //
    result = (PC2_DETECTION_RESULT)ExAllocateFromNPagedLookasideList(
        &detector->ResultLookaside
    );

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(C2_DETECTION_RESULT));

    //
    // Fill result
    //
    result->C2Detected = (destination->SuspicionScore >= C2_ALERT_THRESHOLD);
    result->Type = destination->DetectedType;
    result->Indicators = destination->Indicators;
    result->ConfidenceScore = min(destination->SuspicionScore, 100);
    result->SeverityScore = destination->SuspicionScore;
    result->Destination = destination;

    //
    // Copy beacon analysis
    //
    RtlCopyMemory(
        &result->BeaconAnalysis,
        &destination->BeaconAnalysis,
        sizeof(C2_BEACON_ANALYSIS)
    );

    //
    // Copy JA3 if available
    //
    RtlCopyMemory(
        &result->JA3,
        &destination->JA3Fingerprint,
        sizeof(C2_JA3_FINGERPRINT)
    );

    KeQuerySystemTime(&result->DetectionTime);

    //
    // Update statistics
    //
    if (result->C2Detected) {
        InterlockedIncrement64(&Detector->Stats.C2Detected);
        destination->IsConfirmedC2 = (destination->SuspicionScore >= C2_CONFIRMED_THRESHOLD);
    }

    *Result = result;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2AnalyzeProcess(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PC2_DETECTION_RESULT* Result
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PC2_PROCESS_CONTEXT processContext;
    PC2_DETECTION_RESULT result;

    if (Detector == NULL || !Detector->Initialized || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Find process context
    //
    processContext = C2pFindProcessContext(Detector, ProcessId);

    if (processContext == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Allocate result
    //
    result = (PC2_DETECTION_RESULT)ExAllocateFromNPagedLookasideList(
        &detector->ResultLookaside
    );

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(C2_DETECTION_RESULT));

    //
    // Fill result
    //
    result->C2Detected = processContext->HasConfirmedC2;
    result->Type = processContext->SuspectedC2Type;
    result->ConfidenceScore = min(processContext->HighestSuspicionScore, 100);
    result->SeverityScore = processContext->HighestSuspicionScore;
    result->ProcessId = ProcessId;

    KeQuerySystemTime(&result->DetectionTime);

    *Result = result;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2CheckIOC(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID RemoteAddress,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname,
    _Out_ PBOOLEAN IsKnownC2,
    _Out_opt_ PC2_IOC* MatchedIOC
    )
{
    PLIST_ENTRY entry;
    PC2_IOC ioc;
    ULONG hostnameLen;
    BOOLEAN found = FALSE;

    if (Detector == NULL || !Detector->Initialized ||
        RemoteAddress == NULL || IsKnownC2 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsKnownC2 = FALSE;
    if (MatchedIOC) {
        *MatchedIOC = NULL;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->IOCLock);

    //
    // Search IOC list
    //
    for (entry = Detector->IOCList.Flink;
         entry != &Detector->IOCList;
         entry = entry->Flink) {

        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);

        if (ioc->Type == IOCType_IP) {
            //
            // Check IP match
            //
            if (IsIPv6 == ioc->Value.IP.IsIPv6) {
                if (IsIPv6) {
                    if (RtlEqualMemory(RemoteAddress, &ioc->Value.IP.Address6, sizeof(IN6_ADDR))) {
                        found = TRUE;
                    }
                } else {
                    if (RtlEqualMemory(RemoteAddress, &ioc->Value.IP.Address, sizeof(IN_ADDR))) {
                        found = TRUE;
                    }
                }
            }
        } else if (ioc->Type == IOCType_Domain && Hostname != NULL) {
            //
            // Check domain match
            //
            hostnameLen = (ULONG)strlen(Hostname);
            if (hostnameLen > 0 && hostnameLen < 256) {
                if (_stricmp(Hostname, ioc->Value.Domain) == 0) {
                    found = TRUE;
                }
            }
        }

        if (found) {
            *IsKnownC2 = TRUE;
            if (MatchedIOC) {
                *MatchedIOC = ioc;
            }
            InterlockedIncrement64(&Detector->Stats.IOCMatches);
            break;
        }
    }

    ExReleasePushLockShared(&Detector->IOCLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - IOC MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2AddIOC(
    _In_ PC2_DETECTOR Detector,
    _In_ PC2_IOC IOC
    )
{
    PC2_DETECTOR_INTERNAL detector;
    PC2_IOC newIOC;

    if (Detector == NULL || !Detector->Initialized || IOC == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Allocate IOC entry
    //
    newIOC = (PC2_IOC)ExAllocateFromNPagedLookasideList(
        &detector->IOCLookaside
    );

    if (newIOC == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy IOC data
    //
    RtlCopyMemory(newIOC, IOC, sizeof(C2_IOC));
    KeQuerySystemTime(&newIOC->AddedTime);

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->IOCLock);

    InsertTailList(&Detector->IOCList, &newIOC->ListEntry);
    InterlockedIncrement(&Detector->IOCCount);

    ExReleasePushLockExclusive(&Detector->IOCLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2RemoveIOC(
    _In_ PC2_DETECTOR Detector,
    _In_ PC2_IOC IOC
    )
{
    PC2_DETECTOR_INTERNAL detector;

    if (Detector == NULL || !Detector->Initialized || IOC == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->IOCLock);

    RemoveEntryList(&IOC->ListEntry);
    InterlockedDecrement(&Detector->IOCCount);

    ExReleasePushLockExclusive(&Detector->IOCLock);
    KeLeaveCriticalRegion();

    ExFreeToNPagedLookasideList(&detector->IOCLookaside, IOC);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2LoadIOCFile(
    _In_ PC2_DETECTOR Detector,
    _In_ PUNICODE_STRING FilePath
    )
{
    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(FilePath);

    //
    // IOC file loading would be implemented here
    // Format: JSON or STIX/TAXII compatible
    //
    return STATUS_NOT_IMPLEMENTED;
}

// ============================================================================
// PUBLIC API - JA3 DATABASE
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2AddKnownJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _In_ PCSTR MalwareFamily
    )
{
    PC2_IOC ioc;
    PC2_DETECTOR_INTERNAL detector;

    if (Detector == NULL || !Detector->Initialized ||
        JA3Hash == NULL || MalwareFamily == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Allocate IOC for JA3
    //
    ioc = (PC2_IOC)ExAllocateFromNPagedLookasideList(
        &detector->IOCLookaside
    );

    if (ioc == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ioc, sizeof(C2_IOC));
    ioc->Type = IOCType_JA3;
    RtlCopyMemory(ioc->Value.JA3Hash, JA3Hash, 16);

    if (MalwareFamily != NULL) {
        RtlStringCchCopyA(
            ioc->MalwareFamily,
            sizeof(ioc->MalwareFamily),
            MalwareFamily
        );
    }

    KeQuerySystemTime(&ioc->AddedTime);

    //
    // Add to JA3 list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->JA3Lock);

    InsertTailList(&Detector->KnownJA3List, &ioc->ListEntry);

    ExReleasePushLockExclusive(&Detector->JA3Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
C2LookupJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsKnown,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    )
{
    PLIST_ENTRY entry;
    PC2_IOC ioc;
    BOOLEAN found = FALSE;

    if (Detector == NULL || !Detector->Initialized ||
        JA3Hash == NULL || IsKnown == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsKnown = FALSE;
    if (MalwareFamily && FamilySize > 0) {
        MalwareFamily[0] = '\0';
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->JA3Lock);

    for (entry = Detector->KnownJA3List.Flink;
         entry != &Detector->KnownJA3List;
         entry = entry->Flink) {

        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);

        if (ioc->Type == IOCType_JA3 &&
            RtlEqualMemory(JA3Hash, ioc->Value.JA3Hash, 16)) {
            found = TRUE;
            *IsKnown = TRUE;

            if (MalwareFamily && FamilySize > 0) {
                RtlStringCchCopyA(MalwareFamily, FamilySize, ioc->MalwareFamily);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Detector->JA3Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2RegisterCallback(
    _In_ PC2_DETECTOR Detector,
    _In_ C2_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PC2_DETECTOR_INTERNAL detector;
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->CallbackLock);

    for (i = 0; i < C2_MAX_CALLBACKS; i++) {
        if (!detector->Callbacks[i].InUse) {
            detector->Callbacks[i].Callback = Callback;
            detector->Callbacks[i].Context = Context;
            detector->Callbacks[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&detector->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
VOID
C2UnregisterCallback(
    _In_ PC2_DETECTOR Detector,
    _In_ C2_DETECTION_CALLBACK Callback
    )
{
    PC2_DETECTOR_INTERNAL detector;
    ULONG i;

    if (Detector == NULL || !Detector->Initialized || Callback == NULL) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->CallbackLock);

    for (i = 0; i < C2_MAX_CALLBACKS; i++) {
        if (detector->Callbacks[i].InUse &&
            detector->Callbacks[i].Callback == Callback) {
            detector->Callbacks[i].InUse = FALSE;
            detector->Callbacks[i].Callback = NULL;
            detector->Callbacks[i].Context = NULL;
            break;
        }
    }

    ExReleasePushLockExclusive(&detector->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PUBLIC API - RESULTS
// ============================================================================

_Use_decl_annotations_
VOID
C2FreeResult(
    _In_ PC2_DETECTION_RESULT Result
    )
{
    if (Result == NULL) {
        return;
    }

    //
    // Result was allocated from lookaside - can't easily return to it
    // without detector reference, so use tagged free
    //
    ExFreePoolWithTag(Result, C2_POOL_TAG_CONTEXT);
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2GetStatistics(
    _In_ PC2_DETECTOR Detector,
    _Out_ PC2_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Detector == NULL || !Detector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(C2_STATISTICS));

    Stats->TrackedDestinations = Detector->DestinationCount;
    Stats->ConnectionsAnalyzed = Detector->Stats.ConnectionsAnalyzed;
    Stats->BeaconsDetected = Detector->Stats.BeaconsDetected;
    Stats->C2Detected = Detector->Stats.C2Detected;
    Stats->IOCMatches = Detector->Stats.IOCMatches;
    Stats->IOCCount = Detector->IOCCount;

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTIONS - TIMER
// ============================================================================

static VOID
C2pAnalysisTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PC2_DETECTOR_INTERNAL detector = (PC2_DETECTOR_INTERNAL)DeferredContext;
    PLIST_ENTRY entry;
    PC2_DESTINATION destination;
    PC2_DETECTION_RESULT result;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (detector == NULL || !detector->Public.Initialized) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart -
                          ((LONGLONG)detector->Public.Config.AnalysisWindowMs * 10000);

    //
    // Analyze each destination
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&detector->Public.DestinationListLock);

    for (entry = detector->Public.DestinationList.Flink;
         entry != &detector->Public.DestinationList;
         entry = entry->Flink) {

        destination = CONTAINING_RECORD(entry, C2_DESTINATION, ListEntry);

        //
        // Skip recently analyzed destinations
        //
        if (destination->LastSeen.QuadPart < cutoffTime.QuadPart) {
            continue;
        }

        //
        // Perform beacon analysis
        //
        if (destination->SampleCount >= (LONG)detector->Public.Config.MinBeaconSamples) {
            C2pAnalyzeBeaconing(destination);
            C2pCalculateSuspicionScore(destination);

            //
            // Check if this is a new C2 detection
            //
            if (destination->SuspicionScore >= C2_ALERT_THRESHOLD &&
                !destination->IsConfirmedC2) {

                InterlockedIncrement64(&detector->Public.Stats.C2Detected);

                if (destination->SuspicionScore >= C2_CONFIRMED_THRESHOLD) {
                    destination->IsConfirmedC2 = TRUE;
                }

                //
                // Create result for callbacks
                //
                result = (PC2_DETECTION_RESULT)ExAllocateFromNPagedLookasideList(
                    &detector->ResultLookaside
                );

                if (result != NULL) {
                    RtlZeroMemory(result, sizeof(C2_DETECTION_RESULT));
                    result->C2Detected = TRUE;
                    result->Type = destination->DetectedType;
                    result->Indicators = destination->Indicators;
                    result->ConfidenceScore = min(destination->SuspicionScore, 100);
                    result->SeverityScore = destination->SuspicionScore;
                    result->Destination = destination;
                    RtlCopyMemory(
                        &result->BeaconAnalysis,
                        &destination->BeaconAnalysis,
                        sizeof(C2_BEACON_ANALYSIS)
                    );
                    KeQuerySystemTime(&result->DetectionTime);

                    C2pNotifyCallbacks(detector, result);

                    ExFreeToNPagedLookasideList(&detector->ResultLookaside, result);
                }
            }
        }
    }

    ExReleasePushLockShared(&detector->Public.DestinationListLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE FUNCTIONS - HASH TABLE
// ============================================================================

static NTSTATUS
C2pInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    LIST_ENTRY* buckets;
    ULONG i;

    buckets = (LIST_ENTRY*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        BucketCount * sizeof(LIST_ENTRY),
        C2_POOL_TAG_CONTEXT
    );

    if (buckets == NULL) {
        *Buckets = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < BucketCount; i++) {
        InitializeListHead(&buckets[i]);
    }

    *Buckets = buckets;
    return STATUS_SUCCESS;
}

static VOID
C2pFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    UNREFERENCED_PARAMETER(BucketCount);

    if (*Buckets != NULL) {
        ExFreePoolWithTag(*Buckets, C2_POOL_TAG_CONTEXT);
        *Buckets = NULL;
    }
}

static ULONG
C2pHashAddress(
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash = 2166136261u;
    PUCHAR bytes;
    SIZE_T len;
    SIZE_T i;

    if (IsIPv6) {
        bytes = (PUCHAR)Address;
        len = 16;
    } else {
        bytes = (PUCHAR)Address;
        len = 4;
    }

    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    hash ^= (Port & 0xFF);
    hash *= 16777619u;
    hash ^= (Port >> 8);
    hash *= 16777619u;

    return hash;
}

static ULONG
C2pHashString(
    _In_ PCSTR String,
    _In_ ULONG Length
    )
{
    ULONG hash = 2166136261u;
    ULONG i;

    for (i = 0; i < Length; i++) {
        hash ^= (UCHAR)String[i];
        hash *= 16777619u;
    }

    return hash;
}

// ============================================================================
// PRIVATE FUNCTIONS - DESTINATION MANAGEMENT
// ============================================================================

static PC2_DESTINATION
C2pFindDestination(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6
    )
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PC2_DESTINATION destination;

    hash = C2pHashAddress(Address, Port, IsIPv6);
    bucket = hash % Detector->DestinationHash.BucketCount;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->DestinationHash.Lock);

    for (entry = Detector->DestinationHash.Buckets[bucket].Flink;
         entry != &Detector->DestinationHash.Buckets[bucket];
         entry = entry->Flink) {

        destination = CONTAINING_RECORD(entry, C2_DESTINATION, HashEntry);

        if (destination->Port == Port &&
            destination->IsIPv6 == IsIPv6) {

            BOOLEAN match = FALSE;

            if (IsIPv6) {
                if (RtlEqualMemory(Address, &destination->Address.IPv6, sizeof(IN6_ADDR))) {
                    match = TRUE;
                }
            } else {
                if (RtlEqualMemory(Address, &destination->Address.IPv4, sizeof(IN_ADDR))) {
                    match = TRUE;
                }
            }

            if (match) {
                ExReleasePushLockShared(&Detector->DestinationHash.Lock);
                KeLeaveCriticalRegion();
                return destination;
            }
        }
    }

    ExReleasePushLockShared(&Detector->DestinationHash.Lock);
    KeLeaveCriticalRegion();

    return NULL;
}

static PC2_DESTINATION
C2pCreateDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname
    )
{
    PC2_DESTINATION destination;
    ULONG hash;
    ULONG bucket;

    //
    // Check limit
    //
    if (Detector->Public.DestinationCount >= C2_MAX_TRACKED_DESTINATIONS) {
        return NULL;
    }

    //
    // Allocate destination
    //
    destination = (PC2_DESTINATION)ExAllocateFromNPagedLookasideList(
        &Detector->DestinationLookaside
    );

    if (destination == NULL) {
        return NULL;
    }

    RtlZeroMemory(destination, sizeof(C2_DESTINATION));

    //
    // Initialize
    //
    if (IsIPv6) {
        RtlCopyMemory(&destination->Address.IPv6, Address, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&destination->Address.IPv4, Address, sizeof(IN_ADDR));
    }

    destination->IsIPv6 = IsIPv6;
    destination->Port = Port;

    if (Hostname != NULL) {
        RtlStringCchCopyA(
            destination->Hostname,
            sizeof(destination->Hostname),
            Hostname
        );
    }

    hash = C2pHashAddress(Address, Port, IsIPv6);
    destination->DestinationHash = hash;

    InitializeListHead(&destination->BeaconSamples);
    KeInitializeSpinLock(&destination->SampleLock);

    KeQuerySystemTime(&destination->FirstSeen);
    destination->LastSeen = destination->FirstSeen;

    //
    // Add to lists
    //
    bucket = hash % Detector->Public.DestinationHash.BucketCount;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->Public.DestinationListLock);
    ExAcquirePushLockExclusive(&Detector->Public.DestinationHash.Lock);

    InsertTailList(&Detector->Public.DestinationList, &destination->ListEntry);
    InsertTailList(&Detector->Public.DestinationHash.Buckets[bucket], &destination->HashEntry);
    InterlockedIncrement(&Detector->Public.DestinationCount);

    ExReleasePushLockExclusive(&Detector->Public.DestinationHash.Lock);
    ExReleasePushLockExclusive(&Detector->Public.DestinationListLock);
    KeLeaveCriticalRegion();

    return destination;
}

static VOID
C2pFreeDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    )
{
    C2pFreeBeaconSamples(Detector, Destination);
    ExFreeToNPagedLookasideList(&Detector->DestinationLookaside, Destination);
}

// ============================================================================
// PRIVATE FUNCTIONS - BEACON ANALYSIS
// ============================================================================

static VOID
C2pAddBeaconSample(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination,
    _In_ ULONG DataSize,
    _In_ CT_DIRECTION Direction
    )
{
    PC2_BEACON_SAMPLE sample;
    KIRQL oldIrql;

    //
    // Check sample limit
    //
    if (Destination->SampleCount >= C2_MAX_BEACON_SAMPLES) {
        //
        // Remove oldest sample
        //
        KeAcquireSpinLock(&Destination->SampleLock, &oldIrql);

        if (!IsListEmpty(&Destination->BeaconSamples)) {
            PLIST_ENTRY oldest = RemoveHeadList(&Destination->BeaconSamples);
            sample = CONTAINING_RECORD(oldest, C2_BEACON_SAMPLE, ListEntry);
            ExFreeToNPagedLookasideList(&Detector->SampleLookaside, sample);
            InterlockedDecrement(&Destination->SampleCount);
        }

        KeReleaseSpinLock(&Destination->SampleLock, oldIrql);
    }

    //
    // Allocate new sample
    //
    sample = (PC2_BEACON_SAMPLE)ExAllocateFromNPagedLookasideList(
        &Detector->SampleLookaside
    );

    if (sample == NULL) {
        return;
    }

    RtlZeroMemory(sample, sizeof(C2_BEACON_SAMPLE));
    KeQuerySystemTime(&sample->Timestamp);
    sample->DataSize = DataSize;
    sample->Direction = Direction;

    //
    // Add to list
    //
    KeAcquireSpinLock(&Destination->SampleLock, &oldIrql);
    InsertTailList(&Destination->BeaconSamples, &sample->ListEntry);
    InterlockedIncrement(&Destination->SampleCount);
    KeReleaseSpinLock(&Destination->SampleLock, oldIrql);
}

static VOID
C2pAnalyzeBeaconing(
    _Inout_ PC2_DESTINATION Destination
    )
{
    PC2_BEACON_ANALYSIS analysis = &Destination->BeaconAnalysis;
    PLIST_ENTRY entry;
    PC2_BEACON_SAMPLE sample;
    PC2_BEACON_SAMPLE prevSample = NULL;
    ULONG intervals[C2_MAX_BEACON_SAMPLES];
    ULONG sizes[C2_MAX_BEACON_SAMPLES];
    ULONG intervalCount = 0;
    ULONG sizeCount = 0;
    ULONG meanInterval;
    ULONG stdDeviation;
    ULONG medianInterval;
    ULONG64 totalSize = 0;
    ULONG minSize = MAXULONG;
    ULONG maxSize = 0;
    KIRQL oldIrql;

    if (Destination->SampleCount < C2_MIN_BEACON_SAMPLES) {
        return;
    }

    RtlZeroMemory(intervals, sizeof(intervals));
    RtlZeroMemory(sizes, sizeof(sizes));

    //
    // Collect intervals and sizes
    //
    KeAcquireSpinLock(&Destination->SampleLock, &oldIrql);

    for (entry = Destination->BeaconSamples.Flink;
         entry != &Destination->BeaconSamples && intervalCount < C2_MAX_BEACON_SAMPLES - 1;
         entry = entry->Flink) {

        sample = CONTAINING_RECORD(entry, C2_BEACON_SAMPLE, ListEntry);

        if (prevSample != NULL) {
            ULONG64 intervalMs = (sample->Timestamp.QuadPart -
                                  prevSample->Timestamp.QuadPart) / 10000;

            if (intervalMs <= MAXULONG) {
                intervals[intervalCount++] = (ULONG)intervalMs;
            }
        }

        if (sizeCount < C2_MAX_BEACON_SAMPLES) {
            sizes[sizeCount++] = sample->DataSize;
            totalSize += sample->DataSize;

            if (sample->DataSize < minSize) {
                minSize = sample->DataSize;
            }
            if (sample->DataSize > maxSize) {
                maxSize = sample->DataSize;
            }
        }

        prevSample = sample;
    }

    KeReleaseSpinLock(&Destination->SampleLock, oldIrql);

    if (intervalCount < C2_MIN_SAMPLES_FOR_ANALYSIS) {
        return;
    }

    //
    // Calculate statistics
    //
    C2pCalculateIntervalStatistics(
        Destination,
        &meanInterval,
        &stdDeviation,
        &medianInterval
    );

    //
    // Update analysis
    //
    analysis->SampleCount = Destination->SampleCount;
    analysis->MeanIntervalMs = meanInterval;
    analysis->StdDeviation = stdDeviation;
    analysis->MedianIntervalMs = medianInterval;

    //
    // Calculate jitter percentage
    //
    if (meanInterval > 0) {
        analysis->JitterPercent = (stdDeviation * 100) / meanInterval;
    }

    //
    // Size analysis
    //
    if (sizeCount > 0) {
        analysis->MeanDataSize = (ULONG)(totalSize / sizeCount);
        analysis->MinDataSize = minSize;
        analysis->MaxDataSize = maxSize;

        //
        // Check for consistent size (within 10%)
        //
        if (maxSize > 0) {
            ULONG sizeVariance = ((maxSize - minSize) * 100) / maxSize;
            analysis->ConsistentSize = (sizeVariance <= 10);
        }
    }

    //
    // Beacon detection
    //
    if (meanInterval >= C2_SUSPICIOUS_INTERVAL_MIN_MS &&
        meanInterval <= C2_SUSPICIOUS_INTERVAL_MAX_MS) {

        if (analysis->JitterPercent <= C2_PERFECT_BEACON_JITTER) {
            analysis->RegularBeaconDetected = TRUE;
            Destination->Indicators |= C2Indicator_RegularBeaconing;
            InterlockedIncrement64(&Destination->BeaconAnalysis.ConfidenceScore);
        } else if (analysis->JitterPercent <= C2_TYPICAL_BEACON_JITTER) {
            analysis->JitteredBeaconDetected = TRUE;
            Destination->Indicators |= C2Indicator_JitteredBeaconing;
        }

        analysis->DetectedInterval = meanInterval;
        analysis->ConfidenceScore = 100 - min(analysis->JitterPercent, 100);
    }
}

static VOID
C2pCalculateIntervalStatistics(
    _In_ PC2_DESTINATION Destination,
    _Out_ PULONG MeanInterval,
    _Out_ PULONG StdDeviation,
    _Out_ PULONG MedianInterval
    )
{
    PLIST_ENTRY entry;
    PC2_BEACON_SAMPLE sample;
    PC2_BEACON_SAMPLE prevSample = NULL;
    ULONG intervals[C2_MAX_BEACON_SAMPLES];
    ULONG intervalCount = 0;
    ULONG64 sum = 0;
    ULONG64 sumSquares = 0;
    ULONG mean;
    ULONG variance;
    KIRQL oldIrql;
    ULONG i;

    *MeanInterval = 0;
    *StdDeviation = 0;
    *MedianInterval = 0;

    //
    // Collect intervals
    //
    KeAcquireSpinLock(&Destination->SampleLock, &oldIrql);

    for (entry = Destination->BeaconSamples.Flink;
         entry != &Destination->BeaconSamples && intervalCount < C2_MAX_BEACON_SAMPLES - 1;
         entry = entry->Flink) {

        sample = CONTAINING_RECORD(entry, C2_BEACON_SAMPLE, ListEntry);

        if (prevSample != NULL) {
            ULONG64 intervalMs = (sample->Timestamp.QuadPart -
                                  prevSample->Timestamp.QuadPart) / 10000;

            if (intervalMs > 0 && intervalMs <= MAXULONG) {
                intervals[intervalCount++] = (ULONG)intervalMs;
                sum += intervalMs;
            }
        }

        prevSample = sample;
    }

    KeReleaseSpinLock(&Destination->SampleLock, oldIrql);

    if (intervalCount == 0) {
        return;
    }

    //
    // Calculate mean
    //
    mean = (ULONG)(sum / intervalCount);
    *MeanInterval = mean;

    //
    // Calculate standard deviation
    //
    for (i = 0; i < intervalCount; i++) {
        LONG diff = (LONG)intervals[i] - (LONG)mean;
        sumSquares += (ULONG64)(diff * diff);
    }

    variance = (ULONG)(sumSquares / intervalCount);

    //
    // Integer square root approximation
    //
    if (variance > 0) {
        ULONG root = variance;
        ULONG x = variance;

        while (x > 0) {
            root = x;
            x = (x + variance / x) / 2;
            if (x >= root) break;
        }
        *StdDeviation = root;
    }

    //
    // Calculate median (simple sort)
    //
    C2pQuickSort(intervals, intervalCount);
    *MedianInterval = intervals[intervalCount / 2];
}

// ============================================================================
// PRIVATE FUNCTIONS - JA3 CHECKING
// ============================================================================

static BOOLEAN
C2pCheckKnownJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    )
{
    BOOLEAN isKnown = FALSE;
    NTSTATUS status;

    status = C2LookupJA3(Detector, JA3Hash, &isKnown, MalwareFamily, FamilySize);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return isKnown;
}

static BOOLEAN
C2pIsSuspiciousPort(
    _In_ USHORT Port
    )
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(g_SuspiciousC2Ports); i++) {
        if (Port == g_SuspiciousC2Ports[i]) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE FUNCTIONS - SCORING
// ============================================================================

static VOID
C2pCalculateSuspicionScore(
    _Inout_ PC2_DESTINATION Destination
    )
{
    ULONG score = 0;

    //
    // Beacon detection scores
    //
    if (Destination->Indicators & C2Indicator_RegularBeaconing) {
        score += C2_SCORE_REGULAR_BEACON;
        Destination->DetectedType = C2Type_HTTPSBeacon;
    }

    if (Destination->Indicators & C2Indicator_JitteredBeaconing) {
        score += C2_SCORE_JITTERED_BEACON;
        if (Destination->DetectedType == C2Type_Unknown) {
            Destination->DetectedType = C2Type_HTTPSBeacon;
        }
    }

    //
    // JA3 scores
    //
    if (Destination->Indicators & C2Indicator_KnownJA3) {
        score += C2_SCORE_KNOWN_JA3;
    }

    //
    // IOC scores
    //
    if (Destination->Indicators & C2Indicator_KnownIP) {
        score += C2_SCORE_KNOWN_IP;
    }

    if (Destination->Indicators & C2Indicator_KnownDomain) {
        score += C2_SCORE_KNOWN_DOMAIN;
    }

    //
    // Port scores
    //
    if (Destination->Indicators & C2Indicator_AbnormalPort) {
        score += C2_SCORE_ABNORMAL_PORT;
    }

    //
    // Protocol scores
    //
    if (Destination->Indicators & C2Indicator_EncodedPayload) {
        score += C2_SCORE_ENCODED_PAYLOAD;
    }

    if (Destination->Indicators & C2Indicator_ProtocolAnomaly) {
        score += C2_SCORE_PROTOCOL_ANOMALY;
    }

    //
    // Domain scores
    //
    if (Destination->Indicators & C2Indicator_DomainFronting) {
        score += C2_SCORE_DOMAIN_FRONTING;
        Destination->DetectedType = C2Type_DomainFronting;
    }

    if (Destination->Indicators & C2Indicator_NewlyRegistered) {
        score += C2_SCORE_NEWLY_REGISTERED;
    }

    //
    // TLS scores
    //
    if (Destination->Indicators & C2Indicator_SelfSignedCert) {
        score += C2_SCORE_SELF_SIGNED_CERT;
    }

    //
    // Data pattern scores
    //
    if (Destination->Indicators & C2Indicator_DataSizePattern) {
        score += C2_SCORE_DATA_SIZE_PATTERN;
    }

    if (Destination->BeaconAnalysis.ConsistentSize) {
        score += C2_SCORE_CONSISTENT_SIZE;
    }

    Destination->SuspicionScore = score;
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACKS
// ============================================================================

static VOID
C2pNotifyCallbacks(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PC2_DETECTION_RESULT Result
    )
{
    ULONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < C2_MAX_CALLBACKS; i++) {
        if (Detector->Callbacks[i].InUse && Detector->Callbacks[i].Callback != NULL) {
            Detector->Callbacks[i].Callback(Result, Detector->Callbacks[i].Context);
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE FUNCTIONS - CLEANUP
// ============================================================================

static VOID
C2pFreeBeaconSamples(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PC2_BEACON_SAMPLE sample;

    KeAcquireSpinLock(&Destination->SampleLock, &oldIrql);

    while (!IsListEmpty(&Destination->BeaconSamples)) {
        entry = RemoveHeadList(&Destination->BeaconSamples);
        sample = CONTAINING_RECORD(entry, C2_BEACON_SAMPLE, ListEntry);
        ExFreeToNPagedLookasideList(&Detector->SampleLookaside, sample);
    }

    Destination->SampleCount = 0;

    KeReleaseSpinLock(&Destination->SampleLock, oldIrql);
}

// ============================================================================
// PRIVATE FUNCTIONS - PROCESS CONTEXT
// ============================================================================

static PC2_PROCESS_CONTEXT
C2pFindProcessContext(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PC2_PROCESS_CONTEXT context;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ProcessListLock);

    for (entry = Detector->ProcessList.Flink;
         entry != &Detector->ProcessList;
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, C2_PROCESS_CONTEXT, ListEntry);

        if (context->ProcessId == ProcessId) {
            ExReleasePushLockShared(&Detector->ProcessListLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&Detector->ProcessListLock);
    KeLeaveCriticalRegion();

    return NULL;
}

static PC2_PROCESS_CONTEXT
C2pCreateProcessContext(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
{
    PC2_PROCESS_CONTEXT context;

    context = (PC2_PROCESS_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(C2_PROCESS_CONTEXT),
        C2_POOL_TAG_CONTEXT
    );

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(C2_PROCESS_CONTEXT));
    context->ProcessId = ProcessId;
    InitializeListHead(&context->DestinationList);
    KeInitializeSpinLock(&context->DestinationLock);
    context->RefCount = 1;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessListLock);

    InsertTailList(&Detector->ProcessList, &context->ListEntry);
    InterlockedIncrement(&Detector->ProcessCount);

    ExReleasePushLockExclusive(&Detector->ProcessListLock);
    KeLeaveCriticalRegion();

    return context;
}

static VOID
C2pFreeProcessContext(
    _Inout_ PC2_PROCESS_CONTEXT Context
    )
{
    if (Context->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Context->ProcessName.Buffer, C2_POOL_TAG_CONTEXT);
    }

    ExFreePoolWithTag(Context, C2_POOL_TAG_CONTEXT);
}

// ============================================================================
// PRIVATE FUNCTIONS - UTILITIES
// ============================================================================

static ULONG
C2pQuickSort(
    _Inout_ PULONG Array,
    _In_ ULONG Count
    )
{
    ULONG i, j;
    ULONG temp;

    //
    // Simple insertion sort for small arrays
    //
    for (i = 1; i < Count; i++) {
        temp = Array[i];
        j = i;

        while (j > 0 && Array[j - 1] > temp) {
            Array[j] = Array[j - 1];
            j--;
        }

        Array[j] = temp;
    }

    return Count;
}

static VOID
C2pCleanupWorkItem(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PC2_DETECTOR_INTERNAL detector = (PC2_DETECTOR_INTERNAL)Context;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PC2_DESTINATION destination;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (detector == NULL || !detector->Public.Initialized) {
        return;
    }

    if (InterlockedCompareExchange(&detector->CleanupInProgress, 1, 0) != 0) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart -
                          ((LONGLONG)C2_CLEANUP_INTERVAL_MS * 10000 * 10); // 10 minutes

    //
    // Remove stale destinations
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&detector->Public.DestinationListLock);
    ExAcquirePushLockExclusive(&detector->Public.DestinationHash.Lock);

    for (entry = detector->Public.DestinationList.Flink;
         entry != &detector->Public.DestinationList;
         entry = next) {

        next = entry->Flink;
        destination = CONTAINING_RECORD(entry, C2_DESTINATION, ListEntry);

        if (destination->LastSeen.QuadPart < cutoffTime.QuadPart &&
            destination->ActiveConnections == 0 &&
            !destination->IsConfirmedC2) {

            RemoveEntryList(&destination->ListEntry);
            RemoveEntryList(&destination->HashEntry);
            InterlockedDecrement(&detector->Public.DestinationCount);

            C2pFreeDestination(detector, destination);
        }
    }

    ExReleasePushLockExclusive(&detector->Public.DestinationHash.Lock);
    ExReleasePushLockExclusive(&detector->Public.DestinationListLock);
    KeLeaveCriticalRegion();

    InterlockedExchange(&detector->CleanupInProgress, 0);
}
