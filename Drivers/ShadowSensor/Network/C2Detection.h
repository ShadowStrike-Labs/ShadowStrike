/*++
    ShadowStrike Next-Generation Antivirus
    Module: C2Detection.h
    
    Purpose: Command and Control (C2) communication detection
             through traffic analysis and beaconing detection.
             
    Architecture:
    - Beaconing interval analysis
    - JA3/JA3S fingerprinting
    - Known C2 infrastructure detection
    - Protocol anomaly detection
    
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

#define C2_POOL_TAG_CONTEXT     'XC2C'  // C2 Detection - Context
#define C2_POOL_TAG_BEACON      'BC2C'  // C2 Detection - Beacon
#define C2_POOL_TAG_IOC         'IC2C'  // C2 Detection - IOC

//=============================================================================
// Configuration Constants
//=============================================================================

#define C2_MAX_BEACON_SAMPLES           1024
#define C2_MIN_BEACON_SAMPLES           10
#define C2_BEACON_JITTER_THRESHOLD      20      // Percent
#define C2_MAX_TRACKED_DESTINATIONS     16384
#define C2_ANALYSIS_WINDOW_MS           300000  // 5 minutes
#define C2_JA3_HASH_SIZE                32

//=============================================================================
// C2 Types
//=============================================================================

typedef enum _C2_TYPE {
    C2Type_Unknown = 0,
    C2Type_HTTPBeacon,
    C2Type_HTTPSBeacon,
    C2Type_DNSBeacon,
    C2Type_DNSTunnel,
    C2Type_ICMPTunnel,
    C2Type_CustomProtocol,
    C2Type_EncryptedChannel,
    C2Type_WebSocket,
    C2Type_DomainFronting,
} C2_TYPE;

//=============================================================================
// C2 Indicators
//=============================================================================

typedef enum _C2_INDICATORS {
    C2Indicator_None                = 0x00000000,
    C2Indicator_RegularBeaconing    = 0x00000001,
    C2Indicator_JitteredBeaconing   = 0x00000002,
    C2Indicator_KnownJA3            = 0x00000004,
    C2Indicator_KnownJA3S           = 0x00000008,
    C2Indicator_KnownIP             = 0x00000010,
    C2Indicator_KnownDomain         = 0x00000020,
    C2Indicator_AbnormalPort        = 0x00000040,
    C2Indicator_EncodedPayload      = 0x00000080,
    C2Indicator_LongSleepPattern    = 0x00000100,
    C2Indicator_HighFrequency       = 0x00000200,
    C2Indicator_ProtocolAnomaly     = 0x00000400,
    C2Indicator_DataSizePattern     = 0x00000800,
    C2Indicator_DomainFronting      = 0x00001000,
    C2Indicator_NewlyRegistered     = 0x00002000,
    C2Indicator_SelfSignedCert      = 0x00004000,
} C2_INDICATORS;

//=============================================================================
// Beacon Sample
//=============================================================================

typedef struct _C2_BEACON_SAMPLE {
    LARGE_INTEGER Timestamp;
    ULONG DataSize;
    CT_DIRECTION Direction;
    LIST_ENTRY ListEntry;
} C2_BEACON_SAMPLE, *PC2_BEACON_SAMPLE;

//=============================================================================
// Beacon Analysis
//=============================================================================

typedef struct _C2_BEACON_ANALYSIS {
    //
    // Sample data
    //
    ULONG SampleCount;
    ULONG64 FirstSampleTime;
    ULONG64 LastSampleTime;
    
    //
    // Interval analysis
    //
    ULONG MeanIntervalMs;
    ULONG MedianIntervalMs;
    ULONG MinIntervalMs;
    ULONG MaxIntervalMs;
    ULONG StdDeviation;
    ULONG JitterPercent;                // (StdDev / Mean) * 100
    
    //
    // Size analysis
    //
    ULONG MeanDataSize;
    ULONG MinDataSize;
    ULONG MaxDataSize;
    BOOLEAN ConsistentSize;
    
    //
    // Pattern detection
    //
    BOOLEAN RegularBeaconDetected;
    BOOLEAN JitteredBeaconDetected;
    ULONG DetectedInterval;             // Best-guess interval
    ULONG ConfidenceScore;              // 0-100
    
} C2_BEACON_ANALYSIS, *PC2_BEACON_ANALYSIS;

//=============================================================================
// JA3 Fingerprint
//=============================================================================

typedef struct _C2_JA3_FINGERPRINT {
    CHAR JA3String[512];                // Full JA3 string
    UCHAR JA3Hash[16];                  // MD5 hash
    CHAR JA3SString[512];               // Full JA3S string
    UCHAR JA3SHash[16];                 // MD5 hash
    BOOLEAN IsKnownMalicious;
    CHAR MalwareFamily[64];             // If known
} C2_JA3_FINGERPRINT, *PC2_JA3_FINGERPRINT;

//=============================================================================
// Destination Context
//=============================================================================

typedef struct _C2_DESTINATION {
    //
    // Destination identification
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } Address;
    BOOLEAN IsIPv6;
    USHORT Port;
    CHAR Hostname[256];
    ULONG DestinationHash;
    
    //
    // Connection tracking
    //
    volatile LONG ConnectionCount;
    volatile LONG ActiveConnections;
    LARGE_INTEGER FirstSeen;
    LARGE_INTEGER LastSeen;
    
    //
    // Beacon samples
    //
    LIST_ENTRY BeaconSamples;
    KSPIN_LOCK SampleLock;
    volatile LONG SampleCount;
    
    //
    // Analysis results
    //
    C2_BEACON_ANALYSIS BeaconAnalysis;
    C2_JA3_FINGERPRINT JA3Fingerprint;
    
    //
    // C2 detection
    //
    C2_TYPE DetectedType;
    C2_INDICATORS Indicators;
    ULONG SuspicionScore;
    BOOLEAN IsConfirmedC2;
    
    //
    // Associated processes
    //
    HANDLE AssociatedProcesses[16];
    ULONG ProcessCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} C2_DESTINATION, *PC2_DESTINATION;

//=============================================================================
// Process C2 Context
//=============================================================================

typedef struct _C2_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    
    //
    // Tracked destinations
    //
    LIST_ENTRY DestinationList;
    KSPIN_LOCK DestinationLock;
    volatile LONG DestinationCount;
    
    //
    // C2 suspicion
    //
    ULONG HighestSuspicionScore;
    C2_TYPE SuspectedC2Type;
    BOOLEAN HasConfirmedC2;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} C2_PROCESS_CONTEXT, *PC2_PROCESS_CONTEXT;

//=============================================================================
// IOC Entry
//=============================================================================

typedef struct _C2_IOC {
    enum {
        IOCType_IP,
        IOCType_Domain,
        IOCType_JA3,
        IOCType_JA3S,
        IOCType_UserAgent,
        IOCType_URL
    } Type;
    
    union {
        struct {
            IN_ADDR Address;
            BOOLEAN IsIPv6;
            IN6_ADDR Address6;
        } IP;
        CHAR Domain[256];
        UCHAR JA3Hash[16];
        CHAR UserAgent[256];
        CHAR URL[512];
    } Value;
    
    CHAR MalwareFamily[64];
    CHAR ThreatActor[64];
    LARGE_INTEGER AddedTime;
    LARGE_INTEGER ExpirationTime;
    
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
    
} C2_IOC, *PC2_IOC;

//=============================================================================
// C2 Detection Result
//=============================================================================

typedef struct _C2_DETECTION_RESULT {
    //
    // Detection summary
    //
    BOOLEAN C2Detected;
    C2_TYPE Type;
    C2_INDICATORS Indicators;
    ULONG ConfidenceScore;
    ULONG SeverityScore;
    
    //
    // Source process
    //
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    
    //
    // Destination
    //
    PC2_DESTINATION Destination;
    
    //
    // Beacon analysis
    //
    C2_BEACON_ANALYSIS BeaconAnalysis;
    
    //
    // IOC matches
    //
    struct {
        BOOLEAN Matched;
        PC2_IOC IOC;
    } IOCMatch;
    
    //
    // JA3 analysis
    //
    C2_JA3_FINGERPRINT JA3;
    
    //
    // Threat intelligence
    //
    CHAR MalwareFamily[64];
    CHAR ThreatActor[64];
    CHAR CampaignId[64];
    
    //
    // Timing
    //
    LARGE_INTEGER DetectionTime;
    
} C2_DETECTION_RESULT, *PC2_DETECTION_RESULT;

//=============================================================================
// C2 Detector
//=============================================================================

typedef struct _C2_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Destination tracking
    //
    LIST_ENTRY DestinationList;
    EX_PUSH_LOCK DestinationListLock;
    volatile LONG DestinationCount;
    
    //
    // Destination hash
    //
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
        EX_PUSH_LOCK Lock;
    } DestinationHash;
    
    //
    // Process contexts
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;
    
    //
    // IOC database
    //
    LIST_ENTRY IOCList;
    EX_PUSH_LOCK IOCLock;
    volatile LONG IOCCount;
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } IOCHash;
    
    //
    // Known JA3 fingerprints
    //
    LIST_ENTRY KnownJA3List;
    EX_PUSH_LOCK JA3Lock;
    
    //
    // Analysis timer
    //
    KTIMER AnalysisTimer;
    KDPC AnalysisDpc;
    ULONG AnalysisIntervalMs;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 ConnectionsAnalyzed;
        volatile LONG64 BeaconsDetected;
        volatile LONG64 C2Detected;
        volatile LONG64 IOCMatches;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ULONG MinBeaconSamples;
        ULONG BeaconJitterThreshold;
        ULONG AnalysisWindowMs;
        BOOLEAN EnableJA3Analysis;
        BOOLEAN EnableBeaconDetection;
    } Config;
    
} C2_DETECTOR, *PC2_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*C2_DETECTION_CALLBACK)(
    _In_ PC2_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
C2Initialize(
    _Out_ PC2_DETECTOR* Detector
    );

VOID
C2Shutdown(
    _Inout_ PC2_DETECTOR Detector
    );

//=============================================================================
// Public API - Traffic Recording
//=============================================================================

NTSTATUS
C2RecordConnection(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname
    );

NTSTATUS
C2RecordTraffic(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ ULONG DataSize,
    _In_ CT_DIRECTION Direction
    );

NTSTATUS
C2RecordTLSHandshake(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ PC2_JA3_FINGERPRINT JA3
    );

//=============================================================================
// Public API - Detection
//=============================================================================

NTSTATUS
C2AnalyzeDestination(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _Out_ PC2_DETECTION_RESULT* Result
    );

NTSTATUS
C2AnalyzeProcess(
    _In_ PC2_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PC2_DETECTION_RESULT* Result
    );

NTSTATUS
C2CheckIOC(
    _In_ PC2_DETECTOR Detector,
    _In_ PVOID RemoteAddress,
    _In_ BOOLEAN IsIPv6,
    _In_opt_ PCSTR Hostname,
    _Out_ PBOOLEAN IsKnownC2,
    _Out_opt_ PC2_IOC* MatchedIOC
    );

//=============================================================================
// Public API - IOC Management
//=============================================================================

NTSTATUS
C2AddIOC(
    _In_ PC2_DETECTOR Detector,
    _In_ PC2_IOC IOC
    );

NTSTATUS
C2RemoveIOC(
    _In_ PC2_DETECTOR Detector,
    _In_ PC2_IOC IOC
    );

NTSTATUS
C2LoadIOCFile(
    _In_ PC2_DETECTOR Detector,
    _In_ PUNICODE_STRING FilePath
    );

//=============================================================================
// Public API - JA3 Database
//=============================================================================

NTSTATUS
C2AddKnownJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _In_ PCSTR MalwareFamily
    );

NTSTATUS
C2LookupJA3(
    _In_ PC2_DETECTOR Detector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsKnown,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
C2RegisterCallback(
    _In_ PC2_DETECTOR Detector,
    _In_ C2_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
C2UnregisterCallback(
    _In_ PC2_DETECTOR Detector,
    _In_ C2_DETECTION_CALLBACK Callback
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
C2FreeResult(
    _In_ PC2_DETECTION_RESULT Result
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _C2_STATISTICS {
    ULONG TrackedDestinations;
    ULONG64 ConnectionsAnalyzed;
    ULONG64 BeaconsDetected;
    ULONG64 C2Detected;
    ULONG64 IOCMatches;
    ULONG IOCCount;
    ULONG KnownJA3Count;
    LARGE_INTEGER UpTime;
} C2_STATISTICS, *PC2_STATISTICS;

NTSTATUS
C2GetStatistics(
    _In_ PC2_DETECTOR Detector,
    _Out_ PC2_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
