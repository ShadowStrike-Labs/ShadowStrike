/**
 * ============================================================================
 * ShadowStrike NGAV - ETW PROVIDER
 * ============================================================================
 *
 * @file ETWProvider.h
 * @brief ETW (Event Tracing for Windows) provider for ShadowSensor.
 *
 * This module implements a custom ETW provider for:
 * - High-performance telemetry streaming
 * - Integration with Windows Event Log
 * - SIEM integration via ETW consumers
 * - Real-time diagnostics
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <fltKernel.h>
#include <evntrace.h>
#include "../../Shared/BehaviorTypes.h"
#include "../../Shared/TelemetryTypes.h"

// ============================================================================
// ETW PROVIDER CONFIGURATION
// ============================================================================

/**
 * @brief ShadowStrike ETW Provider GUID.
 */
// {3A5E8B2C-7D4F-4E6A-9C1B-8D0F2E3A4B5C}
DEFINE_GUID(SHADOWSTRIKE_ETW_PROVIDER_GUID,
    0x3a5e8b2c, 0x7d4f, 0x4e6a, 0x9c, 0x1b, 0x8d, 0x0f, 0x2e, 0x3a, 0x4b, 0x5c);

/**
 * @brief Provider name.
 */
#define SHADOWSTRIKE_ETW_PROVIDER_NAME L"ShadowStrike-Security-Sensor"

/**
 * @brief Pool tags.
 */
#define ETW_POOL_TAG_GENERAL    'wEsS'
#define ETW_POOL_TAG_EVENT      'vEsS'
#define ETW_POOL_TAG_BUFFER     'bEsS'

// ============================================================================
// ETW EVENT IDS
// ============================================================================

/**
 * @brief ETW Event IDs.
 */
typedef enum _SHADOWSTRIKE_ETW_EVENT_ID {
    // Process events (1-99)
    EtwEventId_ProcessCreate = 1,
    EtwEventId_ProcessTerminate = 2,
    EtwEventId_ProcessSuspicious = 3,
    EtwEventId_ProcessBlocked = 4,
    
    // Thread events (100-199)
    EtwEventId_ThreadCreate = 100,
    EtwEventId_RemoteThreadCreate = 101,
    EtwEventId_ThreadSuspicious = 102,
    
    // Image load events (200-299)
    EtwEventId_ImageLoad = 200,
    EtwEventId_ImageSuspicious = 201,
    EtwEventId_ImageBlocked = 202,
    
    // File events (300-399)
    EtwEventId_FileCreate = 300,
    EtwEventId_FileWrite = 301,
    EtwEventId_FileScanResult = 302,
    EtwEventId_FileBlocked = 303,
    EtwEventId_FileQuarantined = 304,
    
    // Registry events (400-499)
    EtwEventId_RegistrySetValue = 400,
    EtwEventId_RegistryDeleteValue = 401,
    EtwEventId_RegistrySuspicious = 402,
    EtwEventId_RegistryBlocked = 403,
    
    // Memory events (500-599)
    EtwEventId_MemoryAllocation = 500,
    EtwEventId_MemoryProtectionChange = 501,
    EtwEventId_ShellcodeDetected = 502,
    EtwEventId_InjectionDetected = 503,
    EtwEventId_HollowingDetected = 504,
    
    // Network events (600-699)
    EtwEventId_NetworkConnect = 600,
    EtwEventId_NetworkListen = 601,
    EtwEventId_DnsQuery = 602,
    EtwEventId_C2Detected = 603,
    EtwEventId_ExfiltrationDetected = 604,
    EtwEventId_NetworkBlocked = 605,
    
    // Behavioral events (700-799)
    EtwEventId_BehaviorAlert = 700,
    EtwEventId_AttackChainStarted = 701,
    EtwEventId_AttackChainUpdated = 702,
    EtwEventId_AttackChainCompleted = 703,
    EtwEventId_MitreDetection = 704,
    
    // Security events (800-899)
    EtwEventId_TamperAttempt = 800,
    EtwEventId_EvasionAttempt = 801,
    EtwEventId_DirectSyscall = 802,
    EtwEventId_PrivilegeEscalation = 803,
    EtwEventId_CredentialAccess = 804,
    
    // Diagnostic events (900-999)
    EtwEventId_DriverStarted = 900,
    EtwEventId_DriverStopping = 901,
    EtwEventId_Heartbeat = 902,
    EtwEventId_PerformanceStats = 903,
    EtwEventId_ComponentHealth = 904,
    EtwEventId_Error = 905,
    
    EtwEventId_Max
} SHADOWSTRIKE_ETW_EVENT_ID;

/**
 * @brief ETW Event keywords (for filtering).
 */
#define ETW_KEYWORD_PROCESS           0x0000000000000001ULL
#define ETW_KEYWORD_THREAD            0x0000000000000002ULL
#define ETW_KEYWORD_IMAGE             0x0000000000000004ULL
#define ETW_KEYWORD_FILE              0x0000000000000008ULL
#define ETW_KEYWORD_REGISTRY          0x0000000000000010ULL
#define ETW_KEYWORD_MEMORY            0x0000000000000020ULL
#define ETW_KEYWORD_NETWORK           0x0000000000000040ULL
#define ETW_KEYWORD_BEHAVIOR          0x0000000000000080ULL
#define ETW_KEYWORD_SECURITY          0x0000000000000100ULL
#define ETW_KEYWORD_DIAGNOSTIC        0x0000000000000200ULL
#define ETW_KEYWORD_THREAT            0x0000000000000400ULL
#define ETW_KEYWORD_TELEMETRY         0x0000000000000800ULL

/**
 * @brief ETW Event levels.
 */
#define ETW_LEVEL_CRITICAL            1
#define ETW_LEVEL_ERROR               2
#define ETW_LEVEL_WARNING             3
#define ETW_LEVEL_INFORMATIONAL       4
#define ETW_LEVEL_VERBOSE             5

// ============================================================================
// ETW EVENT STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Common ETW event header.
 */
typedef struct _ETW_EVENT_COMMON {
    UINT64 Timestamp;
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 SessionId;
    UINT32 Reserved;
} ETW_EVENT_COMMON, *PETW_EVENT_COMMON;

/**
 * @brief Process ETW event.
 */
typedef struct _ETW_PROCESS_EVENT {
    ETW_EVENT_COMMON Common;
    UINT32 ParentProcessId;
    UINT32 Flags;
    UINT32 ExitCode;
    UINT32 ThreatScore;
    WCHAR ImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
} ETW_PROCESS_EVENT, *PETW_PROCESS_EVENT;

/**
 * @brief File ETW event.
 */
typedef struct _ETW_FILE_EVENT {
    ETW_EVENT_COMMON Common;
    UINT32 Operation;
    UINT32 Disposition;
    UINT64 FileSize;
    UINT32 ThreatScore;
    UINT32 Verdict;
    WCHAR FilePath[MAX_FILE_PATH_LENGTH];
    WCHAR ThreatName[MAX_THREAT_NAME_LENGTH];
} ETW_FILE_EVENT, *PETW_FILE_EVENT;

/**
 * @brief Network ETW event.
 */
typedef struct _ETW_NETWORK_EVENT {
    ETW_EVENT_COMMON Common;
    UINT32 Protocol;
    UINT32 Direction;
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT32 LocalIpV4;
    UINT32 RemoteIpV4;
    UINT8 LocalIpV6[16];
    UINT8 RemoteIpV6[16];
    UINT64 BytesSent;
    UINT64 BytesReceived;
    UINT32 ThreatScore;
    UINT32 ThreatType;
    WCHAR RemoteHostname[MAX_HOSTNAME_LENGTH];
    WCHAR ProcessPath[MAX_FILE_PATH_LENGTH];
} ETW_NETWORK_EVENT, *PETW_NETWORK_EVENT;

/**
 * @brief Behavioral ETW event.
 */
typedef struct _ETW_BEHAVIOR_EVENT {
    ETW_EVENT_COMMON Common;
    UINT32 BehaviorType;
    UINT32 Category;
    UINT32 ThreatScore;
    UINT32 Confidence;
    UINT64 ChainId;
    UINT32 MitreTechnique;
    UINT32 MitreTactic;
    WCHAR ProcessPath[MAX_FILE_PATH_LENGTH];
    WCHAR Description[512];
} ETW_BEHAVIOR_EVENT, *PETW_BEHAVIOR_EVENT;

/**
 * @brief Security alert ETW event.
 */
typedef struct _ETW_SECURITY_ALERT {
    ETW_EVENT_COMMON Common;
    UINT32 AlertType;
    UINT32 Severity;
    UINT32 ThreatScore;
    UINT32 ResponseAction;
    UINT64 ChainId;
    WCHAR AlertTitle[128];
    WCHAR AlertDescription[512];
    WCHAR ProcessPath[MAX_FILE_PATH_LENGTH];
    WCHAR TargetPath[MAX_FILE_PATH_LENGTH];
} ETW_SECURITY_ALERT, *PETW_SECURITY_ALERT;

#pragma pack(pop)

// ============================================================================
// ETW PROVIDER STATE
// ============================================================================

/**
 * @brief ETW provider global state.
 */
typedef struct _ETW_PROVIDER_GLOBALS {
    // Provider state
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;
    
    // Registration
    REGHANDLE ProviderHandle;
    UCHAR EnableLevel;
    UINT8 Reserved2[3];
    ULONGLONG EnableFlags;
    
    // Consumer info
    UINT32 ConsumerCount;
    UINT32 Reserved3;
    
    // Statistics
    volatile LONG64 EventsWritten;
    volatile LONG64 EventsDropped;
    volatile LONG64 BytesWritten;
    
    // Rate limiting
    volatile LONG EventsThisSecond;
    UINT64 CurrentSecondStart;
    UINT32 MaxEventsPerSecond;
    UINT32 Reserved4;
    
    // Buffers
    NPAGED_LOOKASIDE_LIST EventBufferLookaside;
} ETW_PROVIDER_GLOBALS, *PETW_PROVIDER_GLOBALS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the ETW provider.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwProviderInitialize(VOID);

/**
 * @brief Shutdown the ETW provider.
 */
VOID
EtwProviderShutdown(VOID);

/**
 * @brief Check if ETW is enabled at specified level and keywords.
 * @param Level Event level.
 * @param Keywords Event keywords.
 * @return TRUE if enabled.
 */
BOOLEAN
EtwProviderIsEnabled(
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords
    );

// ============================================================================
// PUBLIC API - EVENT LOGGING
// ============================================================================

/**
 * @brief Write process event.
 * @param EventId Event ID.
 * @param ProcessId Process ID.
 * @param ParentProcessId Parent process ID.
 * @param ImagePath Image path.
 * @param CommandLine Command line.
 * @param ThreatScore Threat score.
 * @param Flags Event flags.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWriteProcessEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags
    );

/**
 * @brief Write file event.
 * @param EventId Event ID.
 * @param ProcessId Process ID.
 * @param FilePath File path.
 * @param Operation File operation.
 * @param FileSize File size.
 * @param Verdict Scan verdict.
 * @param ThreatName Threat name (if malware).
 * @param ThreatScore Threat score.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWriteFileEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ UINT32 Operation,
    _In_ UINT64 FileSize,
    _In_ UINT32 Verdict,
    _In_opt_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore
    );

/**
 * @brief Write network event.
 * @param EventId Event ID.
 * @param Event Network event structure.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWriteNetworkEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ PETW_NETWORK_EVENT Event
    );

/**
 * @brief Write behavioral event.
 * @param EventId Event ID.
 * @param ProcessId Process ID.
 * @param BehaviorType Behavior type.
 * @param Category Behavior category.
 * @param ChainId Attack chain ID.
 * @param MitreTechnique MITRE technique ID.
 * @param ThreatScore Threat score.
 * @param Description Event description.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWriteBehaviorEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 BehaviorType,
    _In_ UINT32 Category,
    _In_ UINT64 ChainId,
    _In_ UINT32 MitreTechnique,
    _In_ UINT32 ThreatScore,
    _In_opt_ PCWSTR Description
    );

/**
 * @brief Write security alert.
 * @param AlertType Alert type.
 * @param Severity Alert severity.
 * @param ProcessId Source process ID.
 * @param ChainId Attack chain ID.
 * @param Title Alert title.
 * @param Description Alert description.
 * @param ProcessPath Process path.
 * @param TargetPath Target path (if applicable).
 * @param ThreatScore Threat score.
 * @param ResponseAction Response taken.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWriteSecurityAlert(
    _In_ UINT32 AlertType,
    _In_ UINT32 Severity,
    _In_ UINT32 ProcessId,
    _In_ UINT64 ChainId,
    _In_ PCWSTR Title,
    _In_ PCWSTR Description,
    _In_opt_ PCWSTR ProcessPath,
    _In_opt_ PCWSTR TargetPath,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 ResponseAction
    );

/**
 * @brief Write diagnostic event.
 * @param EventId Event ID.
 * @param Level Event level.
 * @param ComponentId Component ID.
 * @param Message Diagnostic message.
 * @param ErrorCode Error code (if applicable).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWriteDiagnosticEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UCHAR Level,
    _In_ UINT32 ComponentId,
    _In_ PCWSTR Message,
    _In_ UINT32 ErrorCode
    );

/**
 * @brief Write performance statistics.
 * @param Stats Performance statistics structure.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwWritePerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get ETW provider statistics.
 * @param EventsWritten Output events written.
 * @param EventsDropped Output events dropped.
 * @param BytesWritten Output bytes written.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
EtwProviderGetStatistics(
    _Out_ PUINT64 EventsWritten,
    _Out_ PUINT64 EventsDropped,
    _Out_ PUINT64 BytesWritten
    );

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Log process event if enabled.
 */
#define ETW_LOG_PROCESS(eventId, pid, ppid, path, cmdline, score, flags) \
    do { \
        if (EtwProviderIsEnabled(ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_PROCESS)) { \
            EtwWriteProcessEvent(eventId, pid, ppid, path, cmdline, score, flags); \
        } \
    } while(0)

/**
 * @brief Log threat event if enabled.
 */
#define ETW_LOG_THREAT(eventId, pid, path, threatName, score) \
    do { \
        if (EtwProviderIsEnabled(ETW_LEVEL_WARNING, ETW_KEYWORD_THREAT)) { \
            EtwWriteFileEvent(eventId, pid, path, 0, 0, 0, threatName, score); \
        } \
    } while(0)

/**
 * @brief Log diagnostic event if enabled.
 */
#define ETW_LOG_DIAGNOSTIC(level, component, message) \
    do { \
        if (EtwProviderIsEnabled(level, ETW_KEYWORD_DIAGNOSTIC)) { \
            EtwWriteDiagnosticEvent(EtwEventId_Error, level, component, message, 0); \
        } \
    } while(0)

#endif // SHADOWSTRIKE_ETW_PROVIDER_H
