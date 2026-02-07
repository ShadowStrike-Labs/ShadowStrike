/*++
    ShadowStrike Next-Generation Antivirus
    Module: DataExfiltration.h
    
    Purpose: Data exfiltration detection and prevention (DLP)
             through traffic analysis and content inspection.
             
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

#define DX_POOL_TAG_CONTEXT     'CXXD'  // Data Exfil - Context
#define DX_POOL_TAG_PATTERN     'PXXD'  // Data Exfil - Pattern
#define DX_POOL_TAG_ALERT       'AXXD'  // Data Exfil - Alert

//=============================================================================
// Configuration
//=============================================================================

#define DX_MAX_PATTERNS                 1024
#define DX_MAX_CONTENT_SAMPLE           4096
#define DX_VOLUME_THRESHOLD_MB          100     // Per minute
#define DX_ENTROPY_THRESHOLD            80

//=============================================================================
// Exfiltration Types
//=============================================================================

typedef enum _DX_EXFIL_TYPE {
    DxExfil_Unknown = 0,
    DxExfil_LargeUpload,
    DxExfil_EncodedData,
    DxExfil_EncryptedArchive,
    DxExfil_CloudStorage,
    DxExfil_EmailAttachment,
    DxExfil_DNSTunnel,
    DxExfil_ICMPTunnel,
    DxExfil_SteganoGraphy,
    DxExfil_SensitiveData,
} DX_EXFIL_TYPE;

//=============================================================================
// Exfiltration Indicators
//=============================================================================

typedef enum _DX_INDICATORS {
    DxIndicator_None                = 0x00000000,
    DxIndicator_HighVolume          = 0x00000001,
    DxIndicator_HighEntropy         = 0x00000002,
    DxIndicator_CompressedData      = 0x00000004,
    DxIndicator_EncryptedData       = 0x00000008,
    DxIndicator_EncodedData         = 0x00000010,   // Base64, etc.
    DxIndicator_SensitivePattern    = 0x00000020,
    DxIndicator_UnusualDestination  = 0x00000040,
    DxIndicator_UnusualProtocol     = 0x00000080,
    DxIndicator_UnusualTime         = 0x00000100,   // Off-hours
    DxIndicator_BurstTransfer       = 0x00000200,
    DxIndicator_CloudUpload         = 0x00000400,
    DxIndicator_PersonalEmail       = 0x00000800,
} DX_INDICATORS;

//=============================================================================
// Sensitive Data Pattern
//=============================================================================

typedef struct _DX_PATTERN {
    ULONG PatternId;
    CHAR PatternName[64];
    
    enum {
        PatternType_Regex,
        PatternType_Keyword,
        PatternType_FileSignature,
        PatternType_DataFormat,
    } Type;
    
    PUCHAR Pattern;
    ULONG PatternSize;
    
    enum {
        Sensitivity_Low = 1,
        Sensitivity_Medium = 2,
        Sensitivity_High = 3,
        Sensitivity_Critical = 4,
    } Sensitivity;
    
    CHAR Category[32];                  // PII, Financial, Source Code, etc.
    
    volatile LONG MatchCount;
    
    LIST_ENTRY ListEntry;
    
} DX_PATTERN, *PDX_PATTERN;

//=============================================================================
// Transfer Context
//=============================================================================

typedef struct _DX_TRANSFER_CONTEXT {
    //
    // Transfer identification
    //
    ULONG64 TransferId;
    HANDLE ProcessId;
    
    //
    // Destination
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    BOOLEAN IsIPv6;
    CHAR Hostname[256];
    
    //
    // Transfer statistics
    //
    SIZE_T BytesTransferred;
    SIZE_T BytesPerSecond;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastActivityTime;
    
    //
    // Content analysis
    //
    ULONG Entropy;
    BOOLEAN IsCompressed;
    BOOLEAN IsEncrypted;
    BOOLEAN IsEncoded;
    
    //
    // Pattern matches
    //
    struct {
        PDX_PATTERN Pattern;
        ULONG MatchCount;
    } Matches[16];
    ULONG MatchCount;
    
    //
    // Indicators
    //
    DX_INDICATORS Indicators;
    ULONG SuspicionScore;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} DX_TRANSFER_CONTEXT, *PDX_TRANSFER_CONTEXT;

//=============================================================================
// Exfiltration Alert
//=============================================================================

typedef struct _DX_ALERT {
    //
    // Alert details
    //
    ULONG64 AlertId;
    DX_EXFIL_TYPE Type;
    DX_INDICATORS Indicators;
    ULONG SeverityScore;
    
    //
    // Source
    //
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    UNICODE_STRING UserName;
    
    //
    // Destination
    //
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    BOOLEAN IsIPv6;
    CHAR Hostname[256];
    USHORT RemotePort;
    
    //
    // Transfer details
    //
    SIZE_T DataSize;
    LARGE_INTEGER TransferStartTime;
    ULONG TransferDurationMs;
    
    //
    // Content summary
    //
    struct {
        CHAR Category[32];
        ULONG MatchCount;
    } SensitiveDataFound[8];
    ULONG CategoryCount;
    
    //
    // Action taken
    //
    BOOLEAN WasBlocked;
    
    //
    // Timing
    //
    LARGE_INTEGER AlertTime;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} DX_ALERT, *PDX_ALERT;

//=============================================================================
// Data Exfiltration Detector
//=============================================================================

typedef struct _DX_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Pattern database
    //
    LIST_ENTRY PatternList;
    EX_PUSH_LOCK PatternLock;
    volatile LONG PatternCount;
    
    //
    // Active transfers
    //
    LIST_ENTRY TransferList;
    KSPIN_LOCK TransferLock;
    volatile LONG TransferCount;
    
    //
    // Alerts
    //
    LIST_ENTRY AlertList;
    KSPIN_LOCK AlertLock;
    volatile LONG AlertCount;
    volatile LONG64 NextAlertId;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 BytesInspected;
        volatile LONG64 TransfersAnalyzed;
        volatile LONG64 AlertsGenerated;
        volatile LONG64 TransfersBlocked;
        volatile LONG64 PatternMatches;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        SIZE_T VolumeThresholdPerMinute;
        ULONG EntropyThreshold;
        BOOLEAN EnableContentInspection;
        BOOLEAN EnableCloudDetection;
        BOOLEAN BlockOnDetection;
    } Config;
    
} DX_DETECTOR, *PDX_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*DX_ALERT_CALLBACK)(
    _In_ PDX_ALERT Alert,
    _In_opt_ PVOID Context
    );

typedef BOOLEAN (*DX_BLOCK_CALLBACK)(
    _In_ PDX_TRANSFER_CONTEXT Transfer,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
DxInitialize(
    _Out_ PDX_DETECTOR* Detector
    );

VOID
DxShutdown(
    _Inout_ PDX_DETECTOR Detector
    );

//=============================================================================
// Public API - Pattern Management
//=============================================================================

NTSTATUS
DxAddPattern(
    _In_ PDX_DETECTOR Detector,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR Pattern,
    _In_ ULONG PatternSize,
    _In_ ULONG Sensitivity,
    _In_opt_ PCSTR Category,
    _Out_ PULONG PatternId
    );

NTSTATUS
DxRemovePattern(
    _In_ PDX_DETECTOR Detector,
    _In_ ULONG PatternId
    );

NTSTATUS
DxLoadPatterns(
    _In_ PDX_DETECTOR Detector,
    _In_ PUNICODE_STRING FilePath
    );

//=============================================================================
// Public API - Traffic Analysis
//=============================================================================

NTSTATUS
DxAnalyzeTraffic(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ PULONG SuspicionScore
    );

NTSTATUS
DxRecordTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ SIZE_T BytesSent
    );

//=============================================================================
// Public API - Content Inspection
//=============================================================================

NTSTATUS
DxInspectContent(
    _In_ PDX_DETECTOR Detector,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PDX_INDICATORS Indicators,
    _Out_writes_to_(MaxMatches, *MatchCount) PDX_PATTERN* Matches,
    _In_ ULONG MaxMatches,
    _Out_ PULONG MatchCount
    );

NTSTATUS
DxCalculateEntropy(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PULONG Entropy
    );

//=============================================================================
// Public API - Alerts
//=============================================================================

NTSTATUS
DxGetAlerts(
    _In_ PDX_DETECTOR Detector,
    _Out_writes_to_(MaxAlerts, *AlertCount) PDX_ALERT* Alerts,
    _In_ ULONG MaxAlerts,
    _Out_ PULONG AlertCount
    );

VOID
DxFreeAlert(
    _In_ PDX_ALERT Alert
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
DxRegisterAlertCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

NTSTATUS
DxRegisterBlockCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
DxUnregisterCallbacks(
    _In_ PDX_DETECTOR Detector
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _DX_STATISTICS {
    ULONG64 BytesInspected;
    ULONG64 TransfersAnalyzed;
    ULONG64 AlertsGenerated;
    ULONG64 TransfersBlocked;
    ULONG64 PatternMatches;
    ULONG ActivePatterns;
    LARGE_INTEGER UpTime;
} DX_STATISTICS, *PDX_STATISTICS;

NTSTATUS
DxGetStatistics(
    _In_ PDX_DETECTOR Detector,
    _Out_ PDX_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
