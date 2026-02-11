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
 * Architecture:
 * - Multi-EVENT_DATA_DESCRIPTOR event writing for self-describing events
 * - Per-severity rate limiting (CRITICAL events never dropped)
 * - Atomic enable-state snapshot for lock-free enable tracking
 * - State-machine lifecycle for safe init/shutdown under concurrency
 * - All string parameters bounded by wcsnlen to prevent runaway scans
 * - ReadAcquire-based state checks for ARM64 memory ordering correctness
 * - In-flight writer reference counting with bounded drain timeout
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_ETW_PROVIDER_H
#define SHADOWSTRIKE_ETW_PROVIDER_H

#include <fltKernel.h>
#include <evntrace.h>
#include "../../Shared/BehaviorTypes.h"
#include "../../Shared/TelemetryTypes.h"
#include "../../Shared/NetworkTypes.h"

// ============================================================================
// ETW PROVIDER CONFIGURATION
// ============================================================================

/**
 * @brief ShadowStrike ETW Provider GUID.
 *
 * Declared extern here; defined in ETWProvider.c via INITGUID + DEFINE_GUID.
 * This prevents multiple-definition linker errors when the header is
 * included by more than one translation unit.
 */
// {3A5E8B2C-7D4F-4E6A-9C1B-8D0F2E3A4B5C}
EXTERN_C const GUID SHADOWSTRIKE_ETW_PROVIDER_GUID;

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

/**
 * @brief ETW string field limits for event structures.
 *
 * These are the MAXIMUM character counts written into ETW event payloads.
 * They are deliberately smaller than the SharedDefs maximums to bound
 * per-event NonPaged pool consumption while retaining sufficient fidelity.
 */
#define ETW_MAX_PATH_CHARS              512
#define ETW_MAX_CMDLINE_CHARS           1024
#define ETW_MAX_THREAT_NAME_CHARS       128
#define ETW_MAX_HOSTNAME_CHARS          128
#define ETW_MAX_DESCRIPTION_CHARS       256
#define ETW_MAX_ALERT_TITLE_CHARS       128
#define ETW_MAX_ALERT_DESC_CHARS        256

/**
 * @brief Common ETW event header.
 *
 * Naturally aligned — no #pragma pack needed. All fields are
 * properly aligned to their natural boundaries for atomic access
 * guarantees on x64 and correct behavior on ARM64.
 */
typedef struct _ETW_EVENT_COMMON {
    UINT64 Timestamp;
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 SessionId;
    UINT32 Reserved;
} ETW_EVENT_COMMON, *PETW_EVENT_COMMON;

C_ASSERT(sizeof(ETW_EVENT_COMMON) == 24);
C_ASSERT(FIELD_OFFSET(ETW_EVENT_COMMON, Timestamp) == 0);
C_ASSERT(FIELD_OFFSET(ETW_EVENT_COMMON, ProcessId) == 8);

/**
 * @brief Process ETW event.
 */
typedef struct _ETW_PROCESS_EVENT {
    ETW_EVENT_COMMON Common;
    UINT32 ParentProcessId;
    UINT32 Flags;
    UINT32 ExitCode;
    UINT32 ThreatScore;
    WCHAR ImagePath[ETW_MAX_PATH_CHARS];
    WCHAR CommandLine[ETW_MAX_CMDLINE_CHARS];
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
    WCHAR FilePath[ETW_MAX_PATH_CHARS];
    WCHAR ThreatName[ETW_MAX_THREAT_NAME_CHARS];
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
    WCHAR RemoteHostname[ETW_MAX_HOSTNAME_CHARS];
    WCHAR ProcessPath[ETW_MAX_PATH_CHARS];
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
    WCHAR ProcessPath[ETW_MAX_PATH_CHARS];
    WCHAR Description[ETW_MAX_DESCRIPTION_CHARS];
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
    WCHAR AlertTitle[ETW_MAX_ALERT_TITLE_CHARS];
    WCHAR AlertDescription[ETW_MAX_ALERT_DESC_CHARS];
    WCHAR ProcessPath[ETW_MAX_PATH_CHARS];
    WCHAR TargetPath[ETW_MAX_PATH_CHARS];
} ETW_SECURITY_ALERT, *PETW_SECURITY_ALERT;

// ============================================================================
// ETW PROVIDER LIFECYCLE STATES
// ============================================================================

/**
 * @brief Provider lifecycle state machine.
 *
 * Transitions:
 *   UNINITIALIZED -> INITIALIZING -> READY -> SHUTTING_DOWN -> SHUTDOWN
 * All transitions use InterlockedCompareExchange for atomicity.
 */
typedef enum _ETW_PROVIDER_STATE {
    EtwState_Uninitialized = 0,
    EtwState_Initializing  = 1,
    EtwState_Ready         = 2,
    EtwState_ShuttingDown  = 3,
    EtwState_Shutdown      = 4
} ETW_PROVIDER_STATE;

// ============================================================================
// ETW PROVIDER STATE
// ============================================================================

/**
 * @brief ETW provider global state.
 */
typedef struct _ETW_PROVIDER_GLOBALS {
    // Lifecycle state (ETW_PROVIDER_STATE, accessed via Interlocked)
    volatile LONG State;
    UINT32 Reserved0;

    // Registration
    REGHANDLE ProviderHandle;

    // Enable state (written by callback, read by event writers)
    volatile LONG Enabled;
    UINT32 Reserved3;
    volatile UCHAR EnableLevel;
    UINT8 EnablePadding[7];
    volatile LONGLONG EnableFlags;

    // Statistics
    volatile LONG64 EventsWritten;
    volatile LONG64 EventsDropped;
    volatile LONG64 BytesWritten;

    // Rate limiting
    volatile LONG EventsThisSecond;
    UINT32 Reserved1;
    volatile LONG64 CurrentSecondStart;
    UINT32 MaxEventsPerSecond;
    UINT32 Reserved2;

    // In-flight event writer reference count for safe shutdown
    volatile LONG InFlightWriters;
    UINT32 Reserved4;

    // Lookaside list — sized to the largest event structure
    NPAGED_LOOKASIDE_LIST EventBufferLookaside;
} ETW_PROVIDER_GLOBALS, *PETW_PROVIDER_GLOBALS;

// ============================================================================
// COMPILE-TIME SAFETY ASSERTIONS
// ============================================================================

/**
 * @brief Lookaside buffer size: must accommodate the largest event struct.
 *
 * Computed as the maximum of all event structure sizes, rounded up to
 * the next 256-byte boundary for cache-friendly allocation.
 */
#define ETW_EVENT_MAX_SIZE_RAW \
    ( (sizeof(ETW_PROCESS_EVENT) > sizeof(ETW_FILE_EVENT) ? sizeof(ETW_PROCESS_EVENT) : sizeof(ETW_FILE_EVENT)) > \
      (sizeof(ETW_NETWORK_EVENT) > sizeof(ETW_BEHAVIOR_EVENT) ? sizeof(ETW_NETWORK_EVENT) : sizeof(ETW_BEHAVIOR_EVENT)) \
      ? \
      (sizeof(ETW_PROCESS_EVENT) > sizeof(ETW_FILE_EVENT) ? sizeof(ETW_PROCESS_EVENT) : sizeof(ETW_FILE_EVENT)) \
      : \
      (sizeof(ETW_NETWORK_EVENT) > sizeof(ETW_BEHAVIOR_EVENT) ? sizeof(ETW_NETWORK_EVENT) : sizeof(ETW_BEHAVIOR_EVENT)) \
    )

#define ETW_EVENT_MAX_SIZE_WITH_ALERT \
    (ETW_EVENT_MAX_SIZE_RAW > sizeof(ETW_SECURITY_ALERT) ? ETW_EVENT_MAX_SIZE_RAW : sizeof(ETW_SECURITY_ALERT))

#define ETW_EVENT_BUFFER_SIZE \
    ((ETW_EVENT_MAX_SIZE_WITH_ALERT + 255) & ~(SIZE_T)255)

C_ASSERT(sizeof(ETW_PROCESS_EVENT) <= ETW_EVENT_BUFFER_SIZE);
C_ASSERT(sizeof(ETW_FILE_EVENT) <= ETW_EVENT_BUFFER_SIZE);
C_ASSERT(sizeof(ETW_NETWORK_EVENT) <= ETW_EVENT_BUFFER_SIZE);
C_ASSERT(sizeof(ETW_BEHAVIOR_EVENT) <= ETW_EVENT_BUFFER_SIZE);
C_ASSERT(sizeof(ETW_SECURITY_ALERT) <= ETW_EVENT_BUFFER_SIZE);

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the ETW provider.
 * @return STATUS_SUCCESS on success.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EtwProviderInitialize(VOID);

/**
 * @brief Shutdown the ETW provider.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EtwProviderShutdown(VOID);

/**
 * @brief Check if ETW is enabled at specified level and keywords.
 * @param Level Event level.
 * @param Keywords Event keywords.
 * @return TRUE if enabled.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
 * @param EventId Event ID (must be a process event ID).
 * @param ProcessId Process ID.
 * @param ParentProcessId Parent process ID.
 * @param ImagePath Image path (length-counted, safe).
 * @param CommandLine Command line (length-counted, safe).
 * @param ThreatScore Threat score.
 * @param Flags Event flags.
 * @param ExitCode Process exit code (relevant for terminate events).
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWriteProcessEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags,
    _In_ UINT32 ExitCode
    );

/**
 * @brief Write file event.
 * @param EventId Event ID (must be a file event ID).
 * @param ProcessId Process ID.
 * @param FilePath File path (length-counted, safe).
 * @param Operation File operation.
 * @param FileSize File size.
 * @param Verdict Scan verdict.
 * @param ThreatName Threat name (if malware). Bounded internally.
 * @param ThreatScore Threat score.
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWriteFileEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_opt_ PCUNICODE_STRING FilePath,
    _In_ UINT32 Operation,
    _In_ UINT64 FileSize,
    _In_ UINT32 Verdict,
    _In_opt_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore
    );

/**
 * @brief Write network event.
 *
 * Makes an internal copy of the event structure. Caller's buffer
 * is not modified.
 *
 * @param EventId Event ID (must be a network event ID).
 * @param Event Network event structure (read-only).
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWriteNetworkEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ const ETW_NETWORK_EVENT* Event
    );

/**
 * @brief Write behavioral event.
 * @param EventId Event ID (must be a behavioral event ID).
 * @param ProcessId Process ID.
 * @param BehaviorType Behavior type.
 * @param Category Behavior category.
 * @param ChainId Attack chain ID.
 * @param MitreTechnique MITRE ATT&CK technique ID.
 * @param MitreTactic MITRE ATT&CK tactic ID.
 * @param ThreatScore Threat score.
 * @param Confidence Detection confidence (0-100).
 * @param Description Event description. Bounded internally.
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWriteBehaviorEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 BehaviorType,
    _In_ UINT32 Category,
    _In_ UINT64 ChainId,
    _In_ UINT32 MitreTechnique,
    _In_ UINT32 MitreTactic,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Confidence,
    _In_opt_ PCWSTR Description
    );

/**
 * @brief Write security alert.
 * @param AlertType Alert type (must be a security event ID).
 * @param Severity Alert severity.
 * @param ProcessId Source process ID.
 * @param ChainId Attack chain ID.
 * @param Title Alert title. Bounded internally.
 * @param Description Alert description. Bounded internally.
 * @param ProcessPath Process path. Bounded internally.
 * @param TargetPath Target path (if applicable). Bounded internally.
 * @param ThreatScore Threat score.
 * @param ResponseAction Response taken.
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
 * @param EventId Event ID (must be a diagnostic event ID).
 * @param Level Event level.
 * @param ComponentId Component ID.
 * @param Message Diagnostic message. Bounded internally.
 * @param ErrorCode Error code (if applicable).
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWritePerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get ETW provider statistics (atomic reads).
 * @param EventsWritten Output events written.
 * @param EventsDropped Output events dropped.
 * @param BytesWritten Output bytes written.
 * @return STATUS_SUCCESS on success.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
#define ETW_LOG_PROCESS(eventId, pid, ppid, path, cmdline, score, flags, exitCode) \
    do { \
        if (EtwProviderIsEnabled(ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_PROCESS)) { \
            EtwWriteProcessEvent(eventId, pid, ppid, path, cmdline, score, flags, exitCode); \
        } \
    } while(0)

/**
 * @brief Log threat event if enabled.
 *
 * @param eventId  SHADOWSTRIKE_ETW_EVENT_ID (file event range).
 * @param pid      Process ID (UINT32).
 * @param filePath PCUNICODE_STRING file path (NOT PCWSTR).
 * @param threatName PCWSTR threat name (may be NULL).
 * @param score    Threat score (UINT32).
 */
#define ETW_LOG_THREAT(eventId, pid, filePath, threatName, score) \
    do { \
        if (EtwProviderIsEnabled(ETW_LEVEL_WARNING, ETW_KEYWORD_THREAT)) { \
            PCUNICODE_STRING _etwThreatPath = (filePath); \
            EtwWriteFileEvent(eventId, pid, _etwThreatPath, 0, 0, 0, threatName, score); \
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
