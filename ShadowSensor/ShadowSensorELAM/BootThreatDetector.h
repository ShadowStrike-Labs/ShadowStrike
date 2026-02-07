/*++
    ShadowStrike Next-Generation Antivirus
    Module: BootThreatDetector.h - Boot-time threat detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "BootDriverVerify.h"

#define BTD_POOL_TAG 'DTBE'

typedef enum _BTD_THREAT_TYPE {
    BtdThreat_None = 0,
    BtdThreat_Bootkit,
    BtdThreat_Rootkit,
    BtdThreat_MaliciousDriver,
    BtdThreat_HijackedDriver,
    BtdThreat_VulnerableDriver,
    BtdThreat_UnauthorizedDriver,
} BTD_THREAT_TYPE;

typedef struct _BTD_THREAT {
    BTD_THREAT_TYPE Type;
    UNICODE_STRING DriverPath;
    UCHAR Hash[32];
    
    CHAR ThreatName[64];
    CHAR Description[256];
    
    // Severity
    ULONG SeverityScore;
    BOOLEAN IsCritical;
    
    // Action taken
    BOOLEAN WasBlocked;
    CHAR ActionReason[128];
    
    LARGE_INTEGER DetectionTime;
    LIST_ENTRY ListEntry;
} BTD_THREAT, *PBTD_THREAT;

typedef VOID (*BTD_THREAT_CALLBACK)(
    _In_ PBTD_THREAT Threat,
    _In_opt_ PVOID Context
);

typedef struct _BTD_DETECTOR {
    BOOLEAN Initialized;
    
    // Verifier reference
    PBDV_VERIFIER Verifier;
    
    // Threat database
    LIST_ENTRY ThreatList;
    EX_PUSH_LOCK ThreatLock;
    ULONG ThreatCount;
    
    // Detected threats
    LIST_ENTRY DetectedList;
    KSPIN_LOCK DetectedLock;
    ULONG DetectedCount;
    
    // Callbacks
    BTD_THREAT_CALLBACK ThreatCallback;
    PVOID CallbackContext;
    
    // Vulnerable driver list (BYOVD)
    LIST_ENTRY VulnerableList;
    ULONG VulnerableCount;
    
    struct {
        volatile LONG64 ScansPerformed;
        volatile LONG64 ThreatsDetected;
        volatile LONG64 ThreatsBlocked;
        LARGE_INTEGER StartTime;
    } Stats;
} BTD_DETECTOR, *PBTD_DETECTOR;

NTSTATUS BtdInitialize(_In_ PBDV_VERIFIER Verifier, _Out_ PBTD_DETECTOR* Detector);
VOID BtdShutdown(_Inout_ PBTD_DETECTOR Detector);
NTSTATUS BtdRegisterCallback(_In_ PBTD_DETECTOR Detector, _In_ BTD_THREAT_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS BtdScanDriver(_In_ PBTD_DETECTOR Detector, _In_ PBDV_DRIVER_INFO DriverInfo, _Out_ PBTD_THREAT* Threat);
NTSTATUS BtdLoadVulnerableList(_In_ PBTD_DETECTOR Detector, _In_ PVOID Data, _In_ SIZE_T DataSize);
NTSTATUS BtdIsVulnerable(_In_ PBTD_DETECTOR Detector, _In_ PUCHAR Hash, _In_ SIZE_T HashLength, _Out_ PBOOLEAN IsVulnerable, _Out_opt_ PCHAR* CVE);
NTSTATUS BtdGetThreats(_In_ PBTD_DETECTOR Detector, _Out_writes_to_(Max, *Count) PBTD_THREAT* Threats, _In_ ULONG Max, _Out_ PULONG Count);
VOID BtdFreeThreat(_In_ PBTD_THREAT Threat);

#ifdef __cplusplus
}
#endif
