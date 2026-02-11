/*++
    ShadowStrike Next-Generation Antivirus
    Module: DataExfiltration.h

    Purpose: Data exfiltration detection and prevention (DLP)
             through traffic analysis and content inspection.

    Architecture:
    - All public APIs run at IRQL PASSIVE_LEVEL only.
    - Synchronization uses EX_PUSH_LOCK (PASSIVE/APC safe) throughout.
    - Transfer lookup uses a hash table (O(1) amortized) instead of linear scan.
    - Transfer contexts are reference-counted; DPC cleanup only releases refs.
    - Rundown protection (EX_RUNDOWN_REF) guards shutdown vs in-flight operations.
    - DX_DETECTOR is opaque to consumers; internal state is hidden in .c file.

    MITRE ATT&CK Coverage (implemented):
    - T1041: Exfiltration Over C2 Channel
    - T1567: Exfiltration Over Web Service
    - T1537: Transfer Data to Cloud Account
    - T1030: Data Transfer Size Limits

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

#define DX_POOL_TAG_CONTEXT     'CXXD'
#define DX_POOL_TAG_PATTERN     'PXXD'
#define DX_POOL_TAG_ALERT       'AXXD'

//=============================================================================
// Configuration
//=============================================================================

#define DX_MAX_PATTERNS                 1024
#define DX_MAX_CONTENT_SAMPLE           4096
#define DX_MAX_INSPECT_SIZE             (64 * 1024)  // Max bytes to inspect per call
#define DX_VOLUME_THRESHOLD_MB          100
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
    DxIndicator_EncodedData         = 0x00000010,
    DxIndicator_SensitivePattern    = 0x00000020,
    DxIndicator_UnusualDestination  = 0x00000040,
    DxIndicator_UnusualProtocol     = 0x00000080,
    DxIndicator_UnusualTime         = 0x00000100,
    DxIndicator_BurstTransfer       = 0x00000200,
    DxIndicator_CloudUpload         = 0x00000400,
    DxIndicator_PersonalEmail       = 0x00000800,
} DX_INDICATORS;

//=============================================================================
// Pattern Types
//=============================================================================

typedef enum _DX_PATTERN_TYPE {
    PatternType_Keyword = 0,
    PatternType_FileSignature,
} DX_PATTERN_TYPE;

//=============================================================================
// Sensitive Data Pattern (read-only view for callers)
//=============================================================================

typedef struct _DX_PATTERN {
    ULONG PatternId;
    CHAR PatternName[64];
    DX_PATTERN_TYPE Type;

    PUCHAR Pattern;
    ULONG PatternSize;

    ULONG Sensitivity;          // 1=Low, 2=Medium, 3=High, 4=Critical
    CHAR Category[32];

    volatile LONG MatchCount;
    volatile LONG RefCount;     // Reference count for safe lifetime
    LIST_ENTRY ListEntry;

} DX_PATTERN, *PDX_PATTERN;

//=============================================================================
// Transfer Context (reference-counted)
//=============================================================================

typedef struct _DX_TRANSFER_CONTEXT {
    ULONG64 TransferId;
    HANDLE ProcessId;

    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    BOOLEAN IsIPv6;
    CHAR Hostname[256];

    volatile LONG64 BytesTransferred;
    SIZE_T BytesPerSecond;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastActivityTime;

    ULONG Entropy;
    BOOLEAN IsCompressed;
    BOOLEAN IsEncrypted;
    BOOLEAN IsEncoded;

    //
    // Pattern match snapshots — stores copies of category/sensitivity,
    // not raw pointers to pattern objects (avoids dangling pointer).
    //
    struct {
        CHAR Category[32];
        ULONG Sensitivity;
        ULONG MatchCount;
    } Matches[16];
    ULONG MatchCount;

    DX_INDICATORS Indicators;
    ULONG SuspicionScore;

    //
    // Reference counting for safe lifetime management
    //
    volatile LONG RefCount;

    //
    // Hash table linkage
    //
    LIST_ENTRY HashEntry;

} DX_TRANSFER_CONTEXT, *PDX_TRANSFER_CONTEXT;

//=============================================================================
// Exfiltration Alert
//=============================================================================

typedef struct _DX_ALERT {
    ULONG64 AlertId;
    DX_EXFIL_TYPE Type;
    DX_INDICATORS Indicators;
    ULONG SeverityScore;

    HANDLE ProcessId;
    WCHAR ProcessNameBuffer[260];
    USHORT ProcessNameLength;        // in bytes

    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    BOOLEAN IsIPv6;
    CHAR Hostname[256];
    USHORT RemotePort;

    SIZE_T DataSize;
    LARGE_INTEGER TransferStartTime;
    ULONG TransferDurationMs;

    struct {
        CHAR Category[32];
        ULONG MatchCount;
    } SensitiveDataFound[8];
    ULONG CategoryCount;

    BOOLEAN WasBlocked;
    LARGE_INTEGER AlertTime;
    LIST_ENTRY ListEntry;

} DX_ALERT, *PDX_ALERT;

//=============================================================================
// Opaque Detector Handle
//=============================================================================

//
// DX_DETECTOR is opaque — consumers receive PDX_DETECTOR but cannot
// access internal fields. The full structure is defined only in
// DataExfiltration.c.
//
typedef struct _DX_DETECTOR DX_DETECTOR, *PDX_DETECTOR;

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
// Public API - Initialization (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxInitialize(
    _Out_ PDX_DETECTOR* Detector
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
DxShutdown(
    _Inout_ PDX_DETECTOR Detector
    );

//=============================================================================
// Public API - Pattern Management (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
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

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxRemovePattern(
    _In_ PDX_DETECTOR Detector,
    _In_ ULONG PatternId
    );

//=============================================================================
// Public API - Traffic Analysis (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxAnalyzeTraffic(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(RemoteAddressSize) PVOID RemoteAddress,
    _In_ ULONG RemoteAddressSize,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ PBOOLEAN WasBlocked,
    _Out_opt_ PULONG SuspicionScore
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxRecordTransfer(
    _In_ PDX_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_reads_bytes_(RemoteAddressSize) PVOID RemoteAddress,
    _In_ ULONG RemoteAddressSize,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_ SIZE_T BytesSent
    );

//=============================================================================
// Public API - Content Inspection (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
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

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
DxCalculateEntropy(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Out_ PULONG Entropy
    );

//=============================================================================
// Public API - Alerts (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxGetAlerts(
    _In_ PDX_DETECTOR Detector,
    _Out_writes_to_(MaxAlerts, *AlertCount) PDX_ALERT* Alerts,
    _In_ ULONG MaxAlerts,
    _Out_ PULONG AlertCount
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DxFreeAlert(
    _In_ PDX_DETECTOR Detector,
    _In_ PDX_ALERT Alert
    );

//=============================================================================
// Public API - Callbacks (PASSIVE_LEVEL only)
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxRegisterAlertCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxRegisterBlockCallback(
    _In_ PDX_DETECTOR Detector,
    _In_ DX_BLOCK_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
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

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DxGetStatistics(
    _In_ PDX_DETECTOR Detector,
    _Out_ PDX_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
