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
 * Synchronization model:
 * - All public APIs acquire EX_RUNDOWN_REF for safe shutdown.
 * - All locks are EX_PUSH_LOCK (IRQL <= APC_LEVEL).
 * - No spin locks anywhere. Beacon samples use per-destination push lock.
 * - Timer DPC queues a system work item for PASSIVE_LEVEL analysis.
 * - Destinations and IOCs are reference-counted.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "C2Detection.h"
#include "ConnectionTracker.h"
#include "../Core/Globals.h"
#include "../../Shared/NetworkTypes.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, C2Initialize)
#pragma alloc_text(PAGE, C2Shutdown)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define C2_VERSION                          0x0300
#define C2_HASH_BUCKET_COUNT                1024
#define C2_MAX_CALLBACKS                    8
#define C2_CLEANUP_STALE_AGE_MS             600000
#define C2_ANALYSIS_TIMER_INTERVAL_MS       5000

//
// Beacon detection thresholds
//
#define C2_MIN_SAMPLES_FOR_ANALYSIS         5
#define C2_PERFECT_BEACON_JITTER            5
#define C2_TYPICAL_BEACON_JITTER            25
#define C2_SUSPICIOUS_INTERVAL_MIN_MS       1000
#define C2_SUSPICIOUS_INTERVAL_MAX_MS       3600000

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
    4444, 5555, 6666, 8080, 8443,
    9001, 9050, 31337, 12345, 54321,
};

//
// Known malicious JA3 fingerprints
//
typedef struct _C2_KNOWN_JA3_ENTRY {
    UCHAR Hash[16];
    CHAR Framework[32];
} C2_KNOWN_JA3_ENTRY;

static const C2_KNOWN_JA3_ENTRY g_KnownMaliciousJA3[] = {
    { { 0x72, 0xa5, 0x89, 0xda, 0x58, 0x6c, 0x44, 0x6d, 0xab, 0x21, 0x8e, 0x59, 0x55, 0xc3, 0x0c, 0x86 },
      "CobaltStrike" },
    { { 0x6e, 0x37, 0x9c, 0x0c, 0x0a, 0x8e, 0x4e, 0x80, 0x58, 0x9c, 0x7f, 0xa5, 0x93, 0x3c, 0x65, 0x32 },
      "CobaltStrike" },
    { { 0x3b, 0x5f, 0xc0, 0x67, 0xce, 0xb2, 0xd2, 0x42, 0x28, 0x6f, 0x19, 0x6e, 0xdc, 0x44, 0x5a, 0x4e },
      "Metasploit" },
    { { 0x29, 0xd9, 0x11, 0xb8, 0x15, 0xeb, 0x59, 0x0c, 0x45, 0xe7, 0xf8, 0x5d, 0x87, 0xa1, 0x9c, 0x0a },
      "Empire" },
    { { 0x51, 0xc6, 0x4a, 0xc4, 0x82, 0x16, 0x89, 0xaf, 0xe6, 0x5e, 0x1d, 0x68, 0xd4, 0xb8, 0x34, 0x0d },
      "PoshC2" },
    { { 0x44, 0x8f, 0x1c, 0x2b, 0xa7, 0x89, 0x3c, 0x4d, 0x9e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f },
      "Sliver" },
    { { 0x33, 0x92, 0xde, 0x23, 0x8a, 0x17, 0x4e, 0xc1, 0xc8, 0x6a, 0x9e, 0x51, 0x2b, 0x74, 0xf9, 0x80 },
      "BruteRatel" },
};

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

typedef struct _C2_CALLBACK_ENTRY {
    C2_DETECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN InUse;
} C2_CALLBACK_ENTRY, *PC2_CALLBACK_ENTRY;

// ============================================================================
// INTERNAL DETECTOR STATE
// ============================================================================

typedef struct _C2_DETECTOR_INTERNAL {
    C2_DETECTOR Public;

    C2_CALLBACK_ENTRY Callbacks[C2_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    NPAGED_LOOKASIDE_LIST DestinationLookaside;
    NPAGED_LOOKASIDE_LIST SampleLookaside;
    NPAGED_LOOKASIDE_LIST IOCLookaside;
    BOOLEAN LookasideInitialized;

    PIO_WORKITEM AnalysisWorkItem;
    volatile LONG AnalysisWorkItemQueued;

    PDEVICE_OBJECT DeviceObject;
} C2_DETECTOR_INTERNAL, *PC2_DETECTOR_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID C2pAnalysisTimerDpc(
    _In_ PKDPC Dpc, _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2);

static VOID C2pAnalysisWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context);

static VOID C2pCleanupStaleEntries(
    _In_ PC2_DETECTOR_INTERNAL Detector);

static NTSTATUS C2pInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets, _In_ ULONG BucketCount);

static VOID C2pFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets);

static ULONG C2pHashAddress(
    _In_ PVOID Address, _In_ USHORT Port, _In_ BOOLEAN IsIPv6);

//
// Destination management — all require DestinationLock held by caller
//
static PC2_DESTINATION C2pFindDestinationLocked(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID Address, _In_ USHORT Port, _In_ BOOLEAN IsIPv6);

static PC2_DESTINATION C2pFindOrCreateDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address, _In_ USHORT Port, _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname);

static VOID C2pReferenceDestination(
    _Inout_ PC2_DESTINATION Destination);

static VOID C2pDereferenceDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination);

static VOID C2pFreeDestinationUnsafe(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination);

static VOID C2pFreeBeaconSamples(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination);

static VOID C2pAddBeaconSample(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination,
    _In_ ULONG DataSize, _In_ CT_DIRECTION Direction);

//
// Analysis — runs at PASSIVE_LEVEL
//
static VOID C2pAnalyzeBeaconing(
    _Inout_ PC2_DESTINATION Destination,
    _In_ PULONG IntervalBuffer, _In_ ULONG IntervalBufferCount);

static VOID C2pCalculateIntervalStats(
    _Inout_ PULONG Intervals, _In_ ULONG Count,
    _Out_ PULONG MeanInterval, _Out_ PULONG StdDeviation,
    _Out_ PULONG MedianInterval);

static VOID C2pInsertionSort(
    _Inout_ PULONG Array, _In_ ULONG Count);

static BOOLEAN C2pCheckKnownJA3(
    _In_ PC2_DETECTOR Detector, _In_ PUCHAR JA3Hash,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily, _In_ ULONG FamilySize);

static BOOLEAN C2pIsSuspiciousPort(_In_ USHORT Port);

static VOID C2pCalculateSuspicionScore(
    _Inout_ PC2_DESTINATION Destination);

static VOID C2pNotifyCallbacks(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PC2_DETECTION_RESULT Result);

//
// Process context
//
static PC2_PROCESS_CONTEXT C2pFindOrCreateProcessContext(
    _In_ PC2_DETECTOR Detector, _In_ HANDLE ProcessId);

static VOID C2pFreeProcessContext(
    _Inout_ PC2_PROCESS_CONTEXT Context);

//
// Result helpers
//
static PC2_DETECTION_RESULT C2pAllocateResult(VOID);

static VOID C2pFillResultFromDestination(
    _Out_ PC2_DETECTION_RESULT Result,
    _In_ PC2_DESTINATION Destination);

//
// Rundown helpers
//
#define C2_ACQUIRE_RUNDOWN(det) \
    ExAcquireRundownProtection(&(det)->RundownRef)

#define C2_RELEASE_RUNDOWN(det) \
    ExReleaseRundownProtection(&(det)->RundownRef)

// ============================================================================
// PUBLIC API — INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2Initialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PC2_DETECTOR* Detector
    )
{
    NTSTATUS status;
    PC2_DETECTOR_INTERNAL detector = NULL;
    LARGE_INTEGER timerDue;
    ULONG i;

    PAGED_CODE();

    if (DeviceObject == NULL || Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    detector = (PC2_DETECTOR_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(C2_DETECTOR_INTERNAL),
        C2_POOL_TAG_CONTEXT
    );

    if (detector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // ExAllocatePool2 zeroes memory. Initialize non-zero fields.
    //

    ExInitializeRundownProtection(&detector->Public.RundownRef);

    InitializeListHead(&detector->Public.DestinationList);
    ExInitializePushLock(&detector->Public.DestinationLock);

    InitializeListHead(&detector->Public.ProcessList);
    ExInitializePushLock(&detector->Public.ProcessListLock);

    InitializeListHead(&detector->Public.IOCList);
    ExInitializePushLock(&detector->Public.IOCLock);

    InitializeListHead(&detector->Public.KnownJA3List);
    ExInitializePushLock(&detector->Public.JA3Lock);

    ExInitializePushLock(&detector->CallbackLock);

    KeInitializeEvent(&detector->Public.CleanupCompleteEvent,
                      NotificationEvent, TRUE);

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

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &detector->DestinationLookaside, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(C2_DESTINATION),
        C2_POOL_TAG_CONTEXT, 0);

    ExInitializeNPagedLookasideList(
        &detector->SampleLookaside, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(C2_BEACON_SAMPLE),
        C2_POOL_TAG_BEACON, 0);

    ExInitializeNPagedLookasideList(
        &detector->IOCLookaside, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(C2_IOC),
        C2_POOL_TAG_IOC, 0);

    detector->LookasideInitialized = TRUE;

    //
    // Default configuration
    //
    detector->Public.Config.MinBeaconSamples = C2_MIN_BEACON_SAMPLES;
    detector->Public.Config.BeaconJitterThreshold = C2_BEACON_JITTER_THRESHOLD;
    detector->Public.Config.AnalysisWindowMs = C2_ANALYSIS_WINDOW_MS;
    detector->Public.Config.EnableJA3Analysis = TRUE;
    detector->Public.Config.EnableBeaconDetection = TRUE;

    //
    // Allocate work item for PASSIVE_LEVEL analysis.
    // Must be done before starting the timer/DPC.
    //
    detector->DeviceObject = DeviceObject;
    detector->AnalysisWorkItem = IoAllocateWorkItem(DeviceObject);
    if (detector->AnalysisWorkItem == NULL) {
        ExDeleteNPagedLookasideList(&detector->IOCLookaside);
        ExDeleteNPagedLookasideList(&detector->SampleLookaside);
        ExDeleteNPagedLookasideList(&detector->DestinationLookaside);
        ExFreePoolWithTag(detector->Public.DestinationHash.Buckets, C2_POOL_TAG_CONTEXT);
        ExFreePoolWithTag(detector, C2_POOL_TAG_CONTEXT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Timer + DPC → work item architecture.
    // DPC runs at DISPATCH_LEVEL but only queues a PASSIVE_LEVEL work item.
    //
    KeInitializeTimer(&detector->Public.AnalysisTimer);
    KeInitializeDpc(&detector->Public.AnalysisDpc,
                    C2pAnalysisTimerDpc, detector);
    detector->Public.AnalysisIntervalMs = C2_ANALYSIS_TIMER_INTERVAL_MS;

    timerDue.QuadPart = -((LONGLONG)detector->Public.AnalysisIntervalMs * 10000);
    KeSetTimerEx(&detector->Public.AnalysisTimer, timerDue,
                 detector->Public.AnalysisIntervalMs,
                 &detector->Public.AnalysisDpc);

    KeQuerySystemTime(&detector->Public.Stats.StartTime);

    //
    // Load built-in JA3 fingerprints
    //
    InterlockedExchange(&detector->Public.Initialized, TRUE);

    for (i = 0; i < ARRAYSIZE(g_KnownMaliciousJA3); i++) {
        C2AddKnownJA3(
            &detector->Public,
            (PUCHAR)g_KnownMaliciousJA3[i].Hash,
            g_KnownMaliciousJA3[i].Framework
        );
    }

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

    if (Detector == NULL || !InterlockedExchange(&Detector->Initialized, FALSE)) {
        return;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Cancel timer, flush DPCs, then wait for all in-flight rundown refs.
    //
    KeCancelTimer(&Detector->AnalysisTimer);
    KeFlushQueuedDpcs();
    ExWaitForRundownProtectionRelease(&Detector->RundownRef);

    //
    // At this point no new operations can start and all in-flight ones
    // have completed. We own the detector exclusively.
    //

    //
    // Free all destinations (no lock needed — exclusive ownership)
    //
    while (!IsListEmpty(&Detector->DestinationList)) {
        entry = RemoveHeadList(&Detector->DestinationList);
        destination = CONTAINING_RECORD(entry, C2_DESTINATION, ListEntry);
        C2pFreeBeaconSamples(detector, destination);
        ExFreeToNPagedLookasideList(&detector->DestinationLookaside, destination);
    }

    //
    // Free all process contexts
    //
    while (!IsListEmpty(&Detector->ProcessList)) {
        entry = RemoveHeadList(&Detector->ProcessList);
        processContext = CONTAINING_RECORD(entry, C2_PROCESS_CONTEXT, ListEntry);
        C2pFreeProcessContext(processContext);
    }

    //
    // Free all IOCs
    //
    while (!IsListEmpty(&Detector->IOCList)) {
        entry = RemoveHeadList(&Detector->IOCList);
        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);
        ExFreeToNPagedLookasideList(&detector->IOCLookaside, ioc);
    }

    //
    // Free KnownJA3 list entries
    //
    while (!IsListEmpty(&Detector->KnownJA3List)) {
        entry = RemoveHeadList(&Detector->KnownJA3List);
        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);
        ExFreeToNPagedLookasideList(&detector->IOCLookaside, ioc);
    }

    //
    // Free hash table
    //
    C2pFreeHashTable(&Detector->DestinationHash.Buckets);

    //
    // Delete lookaside lists
    //
    if (detector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&detector->DestinationLookaside);
        ExDeleteNPagedLookasideList(&detector->SampleLookaside);
        ExDeleteNPagedLookasideList(&detector->IOCLookaside);
    }

    //
    // Free work item if allocated
    //
    if (detector->AnalysisWorkItem != NULL) {
        IoFreeWorkItem(detector->AnalysisWorkItem);
        detector->AnalysisWorkItem = NULL;
    }

    ExFreePoolWithTag(detector, C2_POOL_TAG_CONTEXT);
}

// ============================================================================
// PUBLIC API — TRAFFIC RECORDING
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
    ULONG i;

    if (Detector == NULL || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Atomic find-or-create under exclusive lock
    //
    destination = C2pFindOrCreateDestination(
        detector, RemoteAddress, RemotePort, IsIPv6, Hostname);

    if (destination == NULL) {
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // destination is referenced — safe to use outside lock
    //
    InterlockedIncrement(&destination->ConnectionCount);
    InterlockedIncrement(&destination->ActiveConnections);
    KeQuerySystemTime(&destination->LastSeen);

    if (C2pIsSuspiciousPort(RemotePort)) {
        InterlockedOr(&destination->Indicators, C2Indicator_AbnormalPort);
    }

    //
    // Track process association under destination lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->DestinationLock);

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

    ExReleasePushLockExclusive(&Detector->DestinationLock);
    KeLeaveCriticalRegion();

    //
    // Ensure process context exists
    //
    C2pFindOrCreateProcessContext(Detector, ProcessId);

    C2pDereferenceDestination(detector, destination);
    InterlockedIncrement64(&Detector->Stats.ConnectionsAnalyzed);
    C2_RELEASE_RUNDOWN(Detector);

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

    if (Detector == NULL || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    destination = C2pFindOrCreateDestination(
        detector, RemoteAddress, RemotePort, IsIPv6, NULL);

    if (destination == NULL) {
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    C2pAddBeaconSample(detector, destination, DataSize, Direction);
    KeQuerySystemTime(&destination->LastSeen);

    C2pDereferenceDestination(detector, destination);
    C2_RELEASE_RUNDOWN(Detector);

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

    if (Detector == NULL || RemoteAddress == NULL || JA3 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    destination = C2pFindOrCreateDestination(
        detector, RemoteAddress, RemotePort, IsIPv6, NULL);

    if (destination == NULL) {
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Store JA3 under lock (struct copy is not atomic)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->DestinationLock);

    RtlCopyMemory(&destination->JA3Fingerprint, JA3, sizeof(C2_JA3_FINGERPRINT));

    if (Detector->Config.EnableJA3Analysis) {
        if (C2pCheckKnownJA3(Detector, JA3->JA3Hash, malwareFamily, sizeof(malwareFamily))) {
            InterlockedOr(&destination->Indicators, C2Indicator_KnownJA3);
            destination->JA3Fingerprint.IsKnownMalicious = TRUE;
            RtlCopyMemory(destination->JA3Fingerprint.MalwareFamily,
                          malwareFamily,
                          sizeof(destination->JA3Fingerprint.MalwareFamily));
        }
    }

    ExReleasePushLockExclusive(&Detector->DestinationLock);
    KeLeaveCriticalRegion();

    C2pDereferenceDestination(detector, destination);
    C2_RELEASE_RUNDOWN(Detector);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — DETECTION
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
    PULONG intervalBuffer = NULL;

    if (Detector == NULL || RemoteAddress == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Find destination under shared lock, take reference
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->DestinationLock);

    destination = C2pFindDestinationLocked(Detector, RemoteAddress, RemotePort, IsIPv6);
    if (destination != NULL) {
        C2pReferenceDestination(destination);
    }

    ExReleasePushLockShared(&Detector->DestinationLock);
    KeLeaveCriticalRegion();

    if (destination == NULL) {
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_NOT_FOUND;
    }

    //
    // Pool-allocate interval buffer to avoid stack overflow
    //
    intervalBuffer = (PULONG)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        C2_MAX_BEACON_SAMPLES * sizeof(ULONG),
        C2_POOL_TAG_WORK);

    if (intervalBuffer != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Detector->DestinationLock);

        C2pAnalyzeBeaconing(destination, intervalBuffer, C2_MAX_BEACON_SAMPLES);
        C2pCalculateSuspicionScore(destination);

        ExReleasePushLockExclusive(&Detector->DestinationLock);
        KeLeaveCriticalRegion();

        ExFreePoolWithTag(intervalBuffer, C2_POOL_TAG_WORK);
    }

    result = C2pAllocateResult();
    if (result == NULL) {
        C2pDereferenceDestination(detector, destination);
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    C2pFillResultFromDestination(result, destination);

    if (result->C2Detected) {
        InterlockedIncrement64(&Detector->Stats.C2Detected);
        if (destination->SuspicionScore >= C2_CONFIRMED_THRESHOLD) {
            destination->IsConfirmedC2 = TRUE;
        }
    }

    C2pDereferenceDestination(detector, destination);
    C2_RELEASE_RUNDOWN(Detector);

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
    PC2_PROCESS_CONTEXT processContext;
    PC2_DETECTION_RESULT result;

    if (Detector == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Find process context under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->ProcessListLock);

    processContext = NULL;
    {
        PLIST_ENTRY entry;
        PC2_PROCESS_CONTEXT ctx;
        for (entry = Detector->ProcessList.Flink;
             entry != &Detector->ProcessList;
             entry = entry->Flink) {
            ctx = CONTAINING_RECORD(entry, C2_PROCESS_CONTEXT, ListEntry);
            if (ctx->ProcessId == ProcessId) {
                processContext = ctx;
                break;
            }
        }
    }

    if (processContext == NULL) {
        ExReleasePushLockShared(&Detector->ProcessListLock);
        KeLeaveCriticalRegion();
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_NOT_FOUND;
    }

    result = C2pAllocateResult();
    if (result == NULL) {
        ExReleasePushLockShared(&Detector->ProcessListLock);
        KeLeaveCriticalRegion();
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    result->C2Detected = processContext->HasConfirmedC2;
    result->Type = processContext->SuspectedC2Type;
    result->ConfidenceScore = min(processContext->HighestSuspicionScore, 100);
    result->SeverityScore = processContext->HighestSuspicionScore;
    result->ProcessId = ProcessId;
    RtlCopyMemory(result->ProcessName, processContext->ProcessName,
                   sizeof(result->ProcessName));
    KeQuerySystemTime(&result->DetectionTime);

    ExReleasePushLockShared(&Detector->ProcessListLock);
    KeLeaveCriticalRegion();
    C2_RELEASE_RUNDOWN(Detector);

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
    BOOLEAN found = FALSE;

    if (Detector == NULL || RemoteAddress == NULL || IsKnownC2 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsKnownC2 = FALSE;
    if (MatchedIOC) {
        *MatchedIOC = NULL;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->IOCLock);

    for (entry = Detector->IOCList.Flink;
         entry != &Detector->IOCList;
         entry = entry->Flink) {

        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);

        if (ioc->Type == IOCType_IP && IsIPv6 == ioc->Value.IP.IsIPv6) {
            if (IsIPv6) {
                if (RtlEqualMemory(RemoteAddress, &ioc->Value.IP.Address6, sizeof(IN6_ADDR))) {
                    found = TRUE;
                }
            } else {
                if (RtlEqualMemory(RemoteAddress, &ioc->Value.IP.Address, sizeof(IN_ADDR))) {
                    found = TRUE;
                }
            }
        } else if (ioc->Type == IOCType_Domain && Hostname != NULL) {
            ULONG hostnameLen = (ULONG)strlen(Hostname);
            if (hostnameLen > 0 && hostnameLen < 256) {
                if (_stricmp(Hostname, ioc->Value.Domain) == 0) {
                    found = TRUE;
                }
            }
        }

        if (found) {
            *IsKnownC2 = TRUE;
            if (MatchedIOC) {
                //
                // Return referenced IOC pointer. Caller must be aware the
                // pointer is valid only while holding rundown or IOCLock.
                // For safety, take a reference.
                //
                InterlockedIncrement(&ioc->RefCount);
                *MatchedIOC = ioc;
            }
            InterlockedIncrement64(&Detector->Stats.IOCMatches);
            break;
        }
    }

    ExReleasePushLockShared(&Detector->IOCLock);
    KeLeaveCriticalRegion();
    C2_RELEASE_RUNDOWN(Detector);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — IOC MANAGEMENT
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

    if (Detector == NULL || IOC == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    newIOC = (PC2_IOC)ExAllocateFromNPagedLookasideList(&detector->IOCLookaside);
    if (newIOC == NULL) {
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newIOC, IOC, sizeof(C2_IOC));
    KeQuerySystemTime(&newIOC->AddedTime);
    newIOC->RefCount = 1;
    InitializeListHead(&newIOC->ListEntry);
    InitializeListHead(&newIOC->HashEntry);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->IOCLock);
    InsertTailList(&Detector->IOCList, &newIOC->ListEntry);
    InterlockedIncrement(&Detector->IOCCount);
    ExReleasePushLockExclusive(&Detector->IOCLock);
    KeLeaveCriticalRegion();

    C2_RELEASE_RUNDOWN(Detector);
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
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    if (Detector == NULL || IOC == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    //
    // Validate the IOC is actually in our list before removing
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->IOCLock);

    for (entry = Detector->IOCList.Flink;
         entry != &Detector->IOCList;
         entry = entry->Flink) {
        if (entry == &IOC->ListEntry) {
            found = TRUE;
            break;
        }
    }

    if (found) {
        RemoveEntryList(&IOC->ListEntry);
        InterlockedDecrement(&Detector->IOCCount);
    }

    ExReleasePushLockExclusive(&Detector->IOCLock);
    KeLeaveCriticalRegion();

    if (found) {
        ExFreeToNPagedLookasideList(&detector->IOCLookaside, IOC);
    }

    C2_RELEASE_RUNDOWN(Detector);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================================
// PUBLIC API — JA3 DATABASE
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

    if (Detector == NULL || JA3Hash == NULL || MalwareFamily == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    detector = CONTAINING_RECORD(Detector, C2_DETECTOR_INTERNAL, Public);

    ioc = (PC2_IOC)ExAllocateFromNPagedLookasideList(&detector->IOCLookaside);
    if (ioc == NULL) {
        C2_RELEASE_RUNDOWN(Detector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ioc, sizeof(C2_IOC));
    ioc->Type = IOCType_JA3;
    ioc->RefCount = 1;
    RtlCopyMemory(ioc->Value.JA3Hash, JA3Hash, 16);
    RtlStringCchCopyA(ioc->MalwareFamily, sizeof(ioc->MalwareFamily), MalwareFamily);
    KeQuerySystemTime(&ioc->AddedTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->JA3Lock);
    InsertTailList(&Detector->KnownJA3List, &ioc->ListEntry);
    InterlockedIncrement(&Detector->KnownJA3Count);
    ExReleasePushLockExclusive(&Detector->JA3Lock);
    KeLeaveCriticalRegion();

    C2_RELEASE_RUNDOWN(Detector);
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

    if (Detector == NULL || JA3Hash == NULL || IsKnown == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsKnown = FALSE;
    if (MalwareFamily && FamilySize > 0) {
        MalwareFamily[0] = '\0';
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->JA3Lock);

    for (entry = Detector->KnownJA3List.Flink;
         entry != &Detector->KnownJA3List;
         entry = entry->Flink) {

        ioc = CONTAINING_RECORD(entry, C2_IOC, ListEntry);

        if (ioc->Type == IOCType_JA3 &&
            RtlEqualMemory(JA3Hash, ioc->Value.JA3Hash, 16)) {
            *IsKnown = TRUE;
            if (MalwareFamily && FamilySize > 0) {
                RtlStringCchCopyA(MalwareFamily, FamilySize, ioc->MalwareFamily);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Detector->JA3Lock);
    KeLeaveCriticalRegion();
    C2_RELEASE_RUNDOWN(Detector);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — CALLBACKS
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

    if (Detector == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
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
    C2_RELEASE_RUNDOWN(Detector);

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

    if (Detector == NULL || Callback == NULL) {
        return;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
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
    C2_RELEASE_RUNDOWN(Detector);
}

// ============================================================================
// PUBLIC API — RESULTS
// ============================================================================

_Use_decl_annotations_
VOID
C2FreeResult(
    _In_ PC2_DETECTION_RESULT Result
    )
{
    if (Result != NULL) {
        ExFreePoolWithTag(Result, C2_POOL_TAG_RESULT);
    }
}

// ============================================================================
// PUBLIC API — STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
C2GetStatistics(
    _In_ PC2_DETECTOR Detector,
    _Out_ PC2_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Detector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!C2_ACQUIRE_RUNDOWN(Detector)) {
        return STATUS_DELETE_PENDING;
    }

    RtlZeroMemory(Stats, sizeof(C2_STATISTICS));

    Stats->TrackedDestinations = (ULONG)Detector->DestinationCount;
    Stats->TrackedProcesses = (ULONG)Detector->ProcessCount;
    Stats->ConnectionsAnalyzed = Detector->Stats.ConnectionsAnalyzed;
    Stats->BeaconsDetected = Detector->Stats.BeaconsDetected;
    Stats->C2Detected = Detector->Stats.C2Detected;
    Stats->IOCMatches = Detector->Stats.IOCMatches;
    Stats->IOCCount = (ULONG)Detector->IOCCount;
    Stats->KnownJA3Count = (ULONG)Detector->KnownJA3Count;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    C2_RELEASE_RUNDOWN(Detector);
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — TIMER DPC (DISPATCH_LEVEL)
//
// Only queues a work item. Does NO list traversal, lock acquisition, or
// allocation beyond IoQueueWorkItemEx.
// ============================================================================

static VOID
C2pAnalysisTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID Arg1,
    _In_opt_ PVOID Arg2
    )
{
    PC2_DETECTOR_INTERNAL detector = (PC2_DETECTOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    if (detector == NULL || !detector->Public.Initialized) {
        return;
    }

    //
    // Avoid queuing multiple concurrent work items
    //
    if (InterlockedCompareExchange(&detector->AnalysisWorkItemQueued, 1, 0) == 0) {
        if (detector->AnalysisWorkItem != NULL) {
            IoQueueWorkItem(detector->AnalysisWorkItem,
                            C2pAnalysisWorkItemRoutine,
                            DelayedWorkQueue,
                            detector);
        } else {
            InterlockedExchange(&detector->AnalysisWorkItemQueued, 0);
        }
    }
}

// ============================================================================
// PRIVATE — ANALYSIS WORK ITEM (PASSIVE_LEVEL)
// ============================================================================

static VOID
C2pAnalysisWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PC2_DETECTOR_INTERNAL detector = (PC2_DETECTOR_INTERNAL)Context;
    PC2_DETECTOR pub;
    PLIST_ENTRY entry;
    PC2_DESTINATION destination;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    PULONG intervalBuffer = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (detector == NULL) {
        return;
    }

    pub = &detector->Public;

    if (!C2_ACQUIRE_RUNDOWN(pub)) {
        InterlockedExchange(&detector->AnalysisWorkItemQueued, 0);
        return;
    }

    //
    // Pool-allocate scratch buffer for interval analysis (avoids stack overflow)
    //
    intervalBuffer = (PULONG)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        C2_MAX_BEACON_SAMPLES * sizeof(ULONG),
        C2_POOL_TAG_WORK);

    if (intervalBuffer == NULL) {
        InterlockedExchange(&detector->AnalysisWorkItemQueued, 0);
        C2_RELEASE_RUNDOWN(pub);
        return;
    }

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart -
                          ((LONGLONG)pub->Config.AnalysisWindowMs * 10000);

    //
    // Phase 1: Analyze destinations under exclusive lock (PASSIVE_LEVEL — safe).
    //          Collect detection results into a pool-allocated array.
    //          Do NOT invoke callbacks while holding the lock.
    //
    {
#define C2_MAX_PENDING_RESULTS  32
        PC2_DETECTION_RESULT pendingResults = NULL;
        ULONG pendingCount = 0;

        pendingResults = (PC2_DETECTION_RESULT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            C2_MAX_PENDING_RESULTS * sizeof(C2_DETECTION_RESULT),
            C2_POOL_TAG_WORK);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&pub->DestinationLock);

        for (entry = pub->DestinationList.Flink;
             entry != &pub->DestinationList;
             entry = entry->Flink) {

            destination = CONTAINING_RECORD(entry, C2_DESTINATION, ListEntry);

            if (destination->LastSeen.QuadPart < cutoffTime.QuadPart) {
                continue;
            }

            if (destination->SampleCount >= (LONG)pub->Config.MinBeaconSamples) {
                C2pAnalyzeBeaconing(destination, intervalBuffer, C2_MAX_BEACON_SAMPLES);
                C2pCalculateSuspicionScore(destination);

                if (destination->SuspicionScore >= C2_ALERT_THRESHOLD &&
                    !destination->IsConfirmedC2) {

                    InterlockedIncrement64(&pub->Stats.C2Detected);

                    if (destination->SuspicionScore >= C2_CONFIRMED_THRESHOLD) {
                        destination->IsConfirmedC2 = TRUE;
                    }

                    //
                    // Snapshot result for deferred callback notification
                    //
                    if (pendingResults != NULL && pendingCount < C2_MAX_PENDING_RESULTS) {
                        RtlZeroMemory(&pendingResults[pendingCount],
                                      sizeof(C2_DETECTION_RESULT));
                        C2pFillResultFromDestination(&pendingResults[pendingCount],
                                                     destination);
                        pendingResults[pendingCount].C2Detected = TRUE;
                        pendingCount++;
                    }
                }
            }
        }

        ExReleasePushLockExclusive(&pub->DestinationLock);
        KeLeaveCriticalRegion();

        //
        // Phase 2: Notify callbacks OUTSIDE the lock — safe for re-entrant APIs.
        //
        if (pendingResults != NULL) {
            ULONG resultIdx;
            for (resultIdx = 0; resultIdx < pendingCount; resultIdx++) {
                C2pNotifyCallbacks(detector, &pendingResults[resultIdx]);
            }
            ExFreePoolWithTag(pendingResults, C2_POOL_TAG_WORK);
        }
#undef C2_MAX_PENDING_RESULTS
    }

    ExFreePoolWithTag(intervalBuffer, C2_POOL_TAG_WORK);

    //
    // Periodically clean stale entries
    //
    C2pCleanupStaleEntries(detector);

    InterlockedExchange(&detector->AnalysisWorkItemQueued, 0);
    C2_RELEASE_RUNDOWN(pub);
}

// ============================================================================
// PRIVATE — HASH TABLE
// ============================================================================

static NTSTATUS
C2pInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    LIST_ENTRY* buckets;
    ULONG i;

    buckets = (LIST_ENTRY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        BucketCount * sizeof(LIST_ENTRY),
        C2_POOL_TAG_CONTEXT);

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
    _Inout_ LIST_ENTRY** Buckets
    )
{
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
    PUCHAR bytes = (PUCHAR)Address;
    SIZE_T len = IsIPv6 ? 16 : 4;
    SIZE_T i;

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

// ============================================================================
// PRIVATE — DESTINATION MANAGEMENT
//
// Single DestinationLock protects both list and hash table.
// ============================================================================

//
// Caller must hold DestinationLock (shared or exclusive).
//
static PC2_DESTINATION
C2pFindDestinationLocked(
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

    for (entry = Detector->DestinationHash.Buckets[bucket].Flink;
         entry != &Detector->DestinationHash.Buckets[bucket];
         entry = entry->Flink) {

        destination = CONTAINING_RECORD(entry, C2_DESTINATION, HashEntry);

        if (destination->Port == Port && destination->IsIPv6 == IsIPv6) {
            BOOLEAN match;
            if (IsIPv6) {
                match = RtlEqualMemory(Address, &destination->Address.IPv6, sizeof(IN6_ADDR));
            } else {
                match = RtlEqualMemory(Address, &destination->Address.IPv4, sizeof(IN_ADDR));
            }
            if (match) {
                return destination;
            }
        }
    }

    return NULL;
}

//
// Atomic find-or-create. Returns a referenced destination.
//
static PC2_DESTINATION
C2pFindOrCreateDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _In_ PVOID Address,
    _In_ USHORT Port,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname
    )
{
    PC2_DETECTOR pub = &Detector->Public;
    PC2_DESTINATION destination;
    ULONG hash;
    ULONG bucket;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&pub->DestinationLock);

    //
    // Try to find existing
    //
    destination = C2pFindDestinationLocked(pub, Address, Port, IsIPv6);
    if (destination != NULL) {
        C2pReferenceDestination(destination);
        ExReleasePushLockExclusive(&pub->DestinationLock);
        KeLeaveCriticalRegion();
        return destination;
    }

    //
    // Check count limit
    //
    if (pub->DestinationCount >= C2_MAX_TRACKED_DESTINATIONS) {
        ExReleasePushLockExclusive(&pub->DestinationLock);
        KeLeaveCriticalRegion();
        return NULL;
    }

    //
    // Allocate and initialize
    //
    destination = (PC2_DESTINATION)ExAllocateFromNPagedLookasideList(
        &Detector->DestinationLookaside);

    if (destination == NULL) {
        ExReleasePushLockExclusive(&pub->DestinationLock);
        KeLeaveCriticalRegion();
        return NULL;
    }

    RtlZeroMemory(destination, sizeof(C2_DESTINATION));
    destination->RefCount = 1; // Caller's reference

    if (IsIPv6) {
        RtlCopyMemory(&destination->Address.IPv6, Address, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&destination->Address.IPv4, Address, sizeof(IN_ADDR));
    }

    destination->IsIPv6 = IsIPv6;
    destination->Port = Port;

    if (Hostname != NULL) {
        RtlStringCchCopyA(destination->Hostname,
                          sizeof(destination->Hostname), Hostname);
    }

    hash = C2pHashAddress(Address, Port, IsIPv6);
    destination->DestinationHash = hash;

    InitializeListHead(&destination->BeaconSamples);
    ExInitializePushLock(&destination->SampleLock);

    KeQuerySystemTime(&destination->FirstSeen);
    destination->LastSeen = destination->FirstSeen;

    //
    // Insert into list and hash
    //
    bucket = hash % pub->DestinationHash.BucketCount;
    InsertTailList(&pub->DestinationList, &destination->ListEntry);
    InsertTailList(&pub->DestinationHash.Buckets[bucket], &destination->HashEntry);
    InterlockedIncrement(&pub->DestinationCount);

    //
    // Take a second reference for the list ownership
    //
    C2pReferenceDestination(destination);

    ExReleasePushLockExclusive(&pub->DestinationLock);
    KeLeaveCriticalRegion();

    return destination;
}

static VOID
C2pReferenceDestination(
    _Inout_ PC2_DESTINATION Destination
    )
{
    InterlockedIncrement(&Destination->RefCount);
}

static VOID
C2pDereferenceDestination(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    )
{
    LONG newRef = InterlockedDecrement(&Destination->RefCount);
    NT_ASSERT(newRef >= 0);

    if (newRef == 0) {
        C2pFreeDestinationUnsafe(Detector, Destination);
    }
}

static VOID
C2pFreeDestinationUnsafe(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    )
{
    C2pFreeBeaconSamples(Detector, Destination);
    ExFreeToNPagedLookasideList(&Detector->DestinationLookaside, Destination);
}

static VOID
C2pFreeBeaconSamples(
    _In_ PC2_DETECTOR_INTERNAL Detector,
    _Inout_ PC2_DESTINATION Destination
    )
{
    PLIST_ENTRY entry;
    PC2_BEACON_SAMPLE sample;

    //
    // Only called when destination is exclusively owned (refcount 0 or shutdown)
    //
    while (!IsListEmpty(&Destination->BeaconSamples)) {
        entry = RemoveHeadList(&Destination->BeaconSamples);
        sample = CONTAINING_RECORD(entry, C2_BEACON_SAMPLE, ListEntry);
        ExFreeToNPagedLookasideList(&Detector->SampleLookaside, sample);
    }

    Destination->SampleCount = 0;
}

// ============================================================================
// PRIVATE — BEACON SAMPLE RECORDING
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

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Destination->SampleLock);

    //
    // Remove oldest if at capacity
    //
    if (Destination->SampleCount >= C2_MAX_BEACON_SAMPLES) {
        if (!IsListEmpty(&Destination->BeaconSamples)) {
            PLIST_ENTRY oldest = RemoveHeadList(&Destination->BeaconSamples);
            sample = CONTAINING_RECORD(oldest, C2_BEACON_SAMPLE, ListEntry);
            ExFreeToNPagedLookasideList(&Detector->SampleLookaside, sample);
            Destination->SampleCount--;
        }
    }

    //
    // Allocate new sample
    //
    sample = (PC2_BEACON_SAMPLE)ExAllocateFromNPagedLookasideList(
        &Detector->SampleLookaside);

    if (sample != NULL) {
        RtlZeroMemory(sample, sizeof(C2_BEACON_SAMPLE));
        KeQuerySystemTime(&sample->Timestamp);
        sample->DataSize = DataSize;
        sample->Direction = Direction;

        InsertTailList(&Destination->BeaconSamples, &sample->ListEntry);
        Destination->SampleCount++;
    }

    ExReleasePushLockExclusive(&Destination->SampleLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE — BEACON ANALYSIS (PASSIVE_LEVEL)
//
// Caller must hold DestinationLock exclusive. IntervalBuffer is a
// caller-provided pool-allocated scratch buffer.
// ============================================================================

static VOID
C2pAnalyzeBeaconing(
    _Inout_ PC2_DESTINATION Destination,
    _In_ PULONG IntervalBuffer,
    _In_ ULONG IntervalBufferCount
    )
{
    PC2_BEACON_ANALYSIS analysis = &Destination->BeaconAnalysis;
    PLIST_ENTRY entry;
    PC2_BEACON_SAMPLE sample;
    PC2_BEACON_SAMPLE prevSample = NULL;
    ULONG intervalCount = 0;
    ULONG sizeCount = 0;
    ULONG64 totalSize = 0;
    ULONG minSize = MAXULONG;
    ULONG maxSize = 0;
    ULONG minInterval = MAXULONG;
    ULONG maxInterval = 0;
    ULONG meanInterval = 0;
    ULONG stdDeviation = 0;
    ULONG medianInterval = 0;
    LARGE_INTEGER firstTime = {0};
    LARGE_INTEGER lastTime = {0};

    if (Destination->SampleCount < C2_MIN_BEACON_SAMPLES) {
        return;
    }

    //
    // Collect intervals from sample list.
    // SampleLock is a push lock — acquire at APC_LEVEL.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Destination->SampleLock);

    for (entry = Destination->BeaconSamples.Flink;
         entry != &Destination->BeaconSamples &&
         intervalCount < IntervalBufferCount - 1;
         entry = entry->Flink) {

        sample = CONTAINING_RECORD(entry, C2_BEACON_SAMPLE, ListEntry);

        // Track first and last sample timestamps
        if (sizeCount == 0) {
            firstTime = sample->Timestamp;
        }
        lastTime = sample->Timestamp;

        if (prevSample != NULL) {
            ULONG64 intervalMs = (sample->Timestamp.QuadPart -
                                  prevSample->Timestamp.QuadPart) / 10000;
            if (intervalMs > 0 && intervalMs <= MAXULONG) {
                ULONG interval = (ULONG)intervalMs;
                IntervalBuffer[intervalCount++] = interval;
                if (interval < minInterval) minInterval = interval;
                if (interval > maxInterval) maxInterval = interval;
            }
        }

        totalSize += sample->DataSize;
        sizeCount++;
        if (sample->DataSize < minSize) minSize = sample->DataSize;
        if (sample->DataSize > maxSize) maxSize = sample->DataSize;

        prevSample = sample;
    }

    ExReleasePushLockShared(&Destination->SampleLock);
    KeLeaveCriticalRegion();

    if (intervalCount < C2_MIN_SAMPLES_FOR_ANALYSIS) {
        return;
    }

    //
    // Calculate statistics using the pool-allocated buffer
    //
    C2pCalculateIntervalStats(IntervalBuffer, intervalCount,
                              &meanInterval, &stdDeviation, &medianInterval);

    analysis->SampleCount = Destination->SampleCount;
    analysis->FirstSampleTime = (ULONG64)firstTime.QuadPart;
    analysis->LastSampleTime = (ULONG64)lastTime.QuadPart;
    analysis->MeanIntervalMs = meanInterval;
    analysis->StdDeviation = stdDeviation;
    analysis->MedianIntervalMs = medianInterval;
    analysis->MinIntervalMs = (minInterval == MAXULONG) ? 0 : minInterval;
    analysis->MaxIntervalMs = maxInterval;

    if (meanInterval > 0) {
        analysis->JitterPercent = (stdDeviation * 100) / meanInterval;
    } else {
        analysis->JitterPercent = 0;
    }

    if (sizeCount > 0) {
        analysis->MeanDataSize = (ULONG)(totalSize / sizeCount);
        analysis->MinDataSize = minSize;
        analysis->MaxDataSize = maxSize;

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
            InterlockedOr(&Destination->Indicators,
                          (LONG)C2Indicator_RegularBeaconing);
        } else if (analysis->JitterPercent <= C2_TYPICAL_BEACON_JITTER) {
            analysis->JitteredBeaconDetected = TRUE;
            InterlockedOr(&Destination->Indicators,
                          (LONG)C2Indicator_JitteredBeaconing);
        }

        analysis->DetectedInterval = meanInterval;
        analysis->ConfidenceScore = 100 - min(analysis->JitterPercent, 100);
    }
}

// ============================================================================
// PRIVATE — INTERVAL STATISTICS
//
// Operates entirely on the caller-provided array. No locks or allocations.
// ============================================================================

static VOID
C2pCalculateIntervalStats(
    _Inout_ PULONG Intervals,
    _In_ ULONG Count,
    _Out_ PULONG MeanInterval,
    _Out_ PULONG StdDeviation,
    _Out_ PULONG MedianInterval
    )
{
    ULONG64 sum = 0;
    ULONG64 sumSquares = 0;
    ULONG mean;
    ULONG variance;
    ULONG i;

    *MeanInterval = 0;
    *StdDeviation = 0;
    *MedianInterval = 0;

    if (Count == 0) {
        return;
    }

    for (i = 0; i < Count; i++) {
        sum += Intervals[i];
    }

    mean = (ULONG)(sum / Count);
    *MeanInterval = mean;

    for (i = 0; i < Count; i++) {
        LONG diff = (LONG)Intervals[i] - (LONG)mean;
        sumSquares += (ULONG64)((LONG64)diff * diff);
    }

    variance = (ULONG)(sumSquares / Count);

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

    C2pInsertionSort(Intervals, Count);
    *MedianInterval = Intervals[Count / 2];
}

static VOID
C2pInsertionSort(
    _Inout_ PULONG Array,
    _In_ ULONG Count
    )
{
    ULONG i, j, temp;

    for (i = 1; i < Count; i++) {
        temp = Array[i];
        j = i;
        while (j > 0 && Array[j - 1] > temp) {
            Array[j] = Array[j - 1];
            j--;
        }
        Array[j] = temp;
    }
}

// ============================================================================
// PRIVATE — JA3 CHECKING
// ============================================================================

static BOOLEAN
C2pCheckKnownJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    )
{
    //
    // Internal lookup — caller already holds rundown protection.
    // Only acquire JA3Lock, do NOT re-acquire rundown.
    //
    PLIST_ENTRY entry;
    PC2_IOC ioc;
    BOOLEAN found = FALSE;

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
            if (MalwareFamily && FamilySize > 0) {
                RtlStringCchCopyA(MalwareFamily, FamilySize, ioc->MalwareFamily);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Detector->JA3Lock);
    KeLeaveCriticalRegion();

    return found;
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
// PRIVATE — SCORING
//
// Caller must hold DestinationLock exclusive.
// Score is fully recalculated from indicators — no accumulation races.
// ============================================================================

static VOID
C2pCalculateSuspicionScore(
    _Inout_ PC2_DESTINATION Destination
    )
{
    ULONG score = 0;
    LONG indicators = Destination->Indicators;

    if (indicators & C2Indicator_RegularBeaconing) {
        score += C2_SCORE_REGULAR_BEACON;
        Destination->DetectedType = C2Type_HTTPSBeacon;
    }

    if (indicators & C2Indicator_JitteredBeaconing) {
        score += C2_SCORE_JITTERED_BEACON;
        if (Destination->DetectedType == C2Type_Unknown) {
            Destination->DetectedType = C2Type_HTTPSBeacon;
        }
    }

    if (indicators & C2Indicator_KnownJA3)       score += C2_SCORE_KNOWN_JA3;
    if (indicators & C2Indicator_KnownIP)        score += C2_SCORE_KNOWN_IP;
    if (indicators & C2Indicator_KnownDomain)    score += C2_SCORE_KNOWN_DOMAIN;
    if (indicators & C2Indicator_AbnormalPort)    score += C2_SCORE_ABNORMAL_PORT;
    if (indicators & C2Indicator_EncodedPayload)  score += C2_SCORE_ENCODED_PAYLOAD;
    if (indicators & C2Indicator_ProtocolAnomaly) score += C2_SCORE_PROTOCOL_ANOMALY;

    if (indicators & C2Indicator_DomainFronting) {
        score += C2_SCORE_DOMAIN_FRONTING;
        Destination->DetectedType = C2Type_DomainFronting;
    }

    if (indicators & C2Indicator_NewlyRegistered) score += C2_SCORE_NEWLY_REGISTERED;
    if (indicators & C2Indicator_SelfSignedCert)  score += C2_SCORE_SELF_SIGNED_CERT;
    if (indicators & C2Indicator_DataSizePattern) score += C2_SCORE_DATA_SIZE_PATTERN;
    if (indicators & C2Indicator_LongSleepPattern) score += C2_SCORE_LONG_SLEEP;
    if (indicators & C2Indicator_HighFrequency)   score += C2_SCORE_HIGH_FREQUENCY;

    if (Destination->BeaconAnalysis.ConsistentSize) {
        score += C2_SCORE_CONSISTENT_SIZE;
    }

    Destination->SuspicionScore = score;
}

// ============================================================================
// PRIVATE — CALLBACKS
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
// PRIVATE — PROCESS CONTEXT
// ============================================================================

static PC2_PROCESS_CONTEXT
C2pFindOrCreateProcessContext(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PC2_PROCESS_CONTEXT context;

    //
    // Atomic find-or-create under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->ProcessListLock);

    for (entry = Detector->ProcessList.Flink;
         entry != &Detector->ProcessList;
         entry = entry->Flink) {
        context = CONTAINING_RECORD(entry, C2_PROCESS_CONTEXT, ListEntry);
        if (context->ProcessId == ProcessId) {
            ExReleasePushLockExclusive(&Detector->ProcessListLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    //
    // Check limit
    //
    if (Detector->ProcessCount >= C2_MAX_TRACKED_PROCESSES) {
        ExReleasePushLockExclusive(&Detector->ProcessListLock);
        KeLeaveCriticalRegion();
        return NULL;
    }

    //
    // Allocate new context
    //
    context = (PC2_PROCESS_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(C2_PROCESS_CONTEXT),
        C2_POOL_TAG_CONTEXT);

    if (context == NULL) {
        ExReleasePushLockExclusive(&Detector->ProcessListLock);
        KeLeaveCriticalRegion();
        return NULL;
    }

    context->ProcessId = ProcessId;
    context->ProcessName[0] = L'\0';
    InitializeListHead(&context->DestinationList);
    ExInitializePushLock(&context->DestinationLock);
    context->RefCount = 1;

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
    ExFreePoolWithTag(Context, C2_POOL_TAG_CONTEXT);
}

// ============================================================================
// PRIVATE — RESULT ALLOCATION
//
// Results are allocated with ExAllocatePool2 and freed with ExFreePoolWithTag.
// This avoids the lookaside-alloc/pool-free mismatch.
// ============================================================================

static PC2_DETECTION_RESULT
C2pAllocateResult(VOID)
{
    return (PC2_DETECTION_RESULT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(C2_DETECTION_RESULT),
        C2_POOL_TAG_RESULT);
}

static VOID
C2pFillResultFromDestination(
    _Out_ PC2_DETECTION_RESULT Result,
    _In_ PC2_DESTINATION Destination
    )
{
    RtlZeroMemory(Result, sizeof(C2_DETECTION_RESULT));

    Result->C2Detected = (Destination->SuspicionScore >= C2_ALERT_THRESHOLD);
    Result->Type = Destination->DetectedType;
    Result->Indicators = (C2_INDICATORS)Destination->Indicators;
    Result->ConfidenceScore = min(Destination->SuspicionScore, 100);
    Result->SeverityScore = Destination->SuspicionScore;

    //
    // Snapshot destination identity (no raw pointer stored)
    //
    if (Destination->IsIPv6) {
        RtlCopyMemory(&Result->Destination.Address.IPv6,
                       &Destination->Address.IPv6, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&Result->Destination.Address.IPv4,
                       &Destination->Address.IPv4, sizeof(IN_ADDR));
    }
    Result->Destination.IsIPv6 = Destination->IsIPv6;
    Result->Destination.Port = Destination->Port;
    RtlCopyMemory(Result->Destination.Hostname, Destination->Hostname,
                   sizeof(Result->Destination.Hostname));

    RtlCopyMemory(&Result->BeaconAnalysis, &Destination->BeaconAnalysis,
                   sizeof(C2_BEACON_ANALYSIS));
    RtlCopyMemory(&Result->JA3, &Destination->JA3Fingerprint,
                   sizeof(C2_JA3_FINGERPRINT));

    KeQuerySystemTime(&Result->DetectionTime);
}

// ============================================================================
// PRIVATE — STALE ENTRY CLEANUP (PASSIVE_LEVEL)
// ============================================================================

static VOID
C2pCleanupStaleEntries(
    _In_ PC2_DETECTOR_INTERNAL Detector
    )
{
    PC2_DETECTOR pub = &Detector->Public;
    PLIST_ENTRY entry, next;
    PC2_DESTINATION destination;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;

    if (InterlockedCompareExchange(&pub->CleanupInProgress, 1, 0) != 0) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart -
                          ((LONGLONG)C2_CLEANUP_STALE_AGE_MS * 10000);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&pub->DestinationLock);

    for (entry = pub->DestinationList.Flink;
         entry != &pub->DestinationList;
         entry = next) {

        next = entry->Flink;
        destination = CONTAINING_RECORD(entry, C2_DESTINATION, ListEntry);

        if (destination->LastSeen.QuadPart < cutoffTime.QuadPart &&
            destination->ActiveConnections == 0 &&
            !destination->IsConfirmedC2) {

            RemoveEntryList(&destination->ListEntry);
            RemoveEntryList(&destination->HashEntry);
            InterlockedDecrement(&pub->DestinationCount);

            //
            // Release the list's reference. If this was the last ref
            // the destination is freed.
            //
            C2pDereferenceDestination(Detector, destination);
        }
    }

    ExReleasePushLockExclusive(&pub->DestinationLock);
    KeLeaveCriticalRegion();

    InterlockedExchange(&pub->CleanupInProgress, 0);
    KeSetEvent(&pub->CleanupCompleteEvent, IO_NO_INCREMENT, FALSE);
}
