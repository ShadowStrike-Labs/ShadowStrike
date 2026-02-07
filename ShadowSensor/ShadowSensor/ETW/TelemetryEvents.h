/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ETW TELEMETRY ENGINE
 * ============================================================================
 *
 * @file TelemetryEvents.h
 * @brief Enterprise-grade ETW telemetry for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level telemetry streaming with:
 * - High-performance ETW event emission (10M+ events/sec capable)
 * - Lock-free event buffering with batch processing
 * - Automatic rate limiting and throttling
 * - SIEM-ready event schemas (ECS compatible)
 * - Attack chain correlation and MITRE ATT&CK mapping
 * - Real-time behavioral telemetry streaming
 * - Configurable verbosity levels per category
 * - Secure event serialization with integrity checks
 * - Memory-efficient lookaside-based event allocation
 * - Graceful degradation under memory pressure
 *
 * Security Guarantees:
 * - No sensitive data logged (PII/credentials filtered)
 * - Tamper-evident event sequencing
 * - Rate limiting prevents DoS via event flooding
 * - All events include cryptographic correlation IDs
 *
 * Performance Guarantees:
 * - Lock-free event submission path
 * - Batched ETW writes reduce syscall overhead
 * - Lookaside lists for zero-allocation hot path
 * - Per-CPU event buffers eliminate contention
 * - Adaptive throttling preserves system stability
 *
 * MITRE ATT&CK Coverage:
 * - Full technique ID embedding in events
 * - Kill chain stage tracking
 * - Attack chain correlation across events
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_TELEMETRY_EVENTS_H_
#define _SHADOWSTRIKE_TELEMETRY_EVENTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <evntrace.h>
#include <evntprov.h>
#include "ETWProvider.h"
#include "EventSchema.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Sync/SpinLock.h"
#include "../../Shared/BehaviorTypes.h"
#include "../../Shared/TelemetryTypes.h"
#include "../../Shared/SharedDefs.h"

// ============================================================================
// ETW PROVIDER CONFIGURATION
// ============================================================================

/**
 * @brief ShadowStrike Telemetry ETW Provider GUID.
 * {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
 */
DEFINE_GUID(SHADOWSTRIKE_TELEMETRY_PROVIDER_GUID,
    0xA1B2C3D4, 0xE5F6, 0x7890, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90);

/**
 * @brief Provider name for ETW registration.
 */
#define TE_PROVIDER_NAME            L"ShadowStrike-Telemetry-Provider"

// ============================================================================
// POOL TAGS
// ============================================================================

#define TE_POOL_TAG                 'ETET'  // Telemetry Events Tag
#define TE_EVENT_TAG                'vEET'  // Event buffer tag
#define TE_BATCH_TAG                'bEET'  // Batch buffer tag
#define TE_CONTEXT_TAG              'cEET'  // Context tag
#define TE_STRING_TAG               'sEET'  // String buffer tag

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/**
 * @brief Maximum events per second before throttling.
 */
#define TE_MAX_EVENTS_PER_SECOND            100000

/**
 * @brief Maximum events in batch before flush.
 */
#define TE_MAX_BATCH_SIZE                   64

/**
 * @brief Maximum batch age in milliseconds before forced flush.
 */
#define TE_MAX_BATCH_AGE_MS                 100

/**
 * @brief Event buffer lookaside list depth.
 */
#define TE_LOOKASIDE_DEPTH                  512

/**
 * @brief Maximum pending events before dropping.
 */
#define TE_MAX_PENDING_EVENTS               10000

/**
 * @brief Maximum string length in events.
 */
#define TE_MAX_STRING_LENGTH                2048

/**
 * @brief Maximum event data size.
 */
#define TE_MAX_EVENT_DATA_SIZE              (16 * 1024)

/**
 * @brief Heartbeat interval in milliseconds.
 */
#define TE_HEARTBEAT_INTERVAL_MS            30000

/**
 * @brief Statistics snapshot interval in milliseconds.
 */
#define TE_STATS_INTERVAL_MS                60000

/**
 * @brief Number of per-CPU event buffers.
 */
#define TE_MAX_CPU_BUFFERS                  64

// ============================================================================
// EVENT LEVELS AND KEYWORDS
// ============================================================================

/**
 * @brief Telemetry event levels (ETW compatible).
 */
typedef enum _TE_EVENT_LEVEL {
    TeLevel_Critical        = 1,    ///< Critical errors, system failures
    TeLevel_Error           = 2,    ///< Errors requiring attention
    TeLevel_Warning         = 3,    ///< Warnings, potential issues
    TeLevel_Informational   = 4,    ///< Normal operational events
    TeLevel_Verbose         = 5     ///< Detailed diagnostic events
} TE_EVENT_LEVEL;

/**
 * @brief Telemetry event keywords (bitmask for filtering).
 */
typedef enum _TE_EVENT_KEYWORD {
    TeKeyword_None          = 0x0000000000000000ULL,

    // Activity categories
    TeKeyword_Process       = 0x0000000000000001ULL,    ///< Process events
    TeKeyword_Thread        = 0x0000000000000002ULL,    ///< Thread events
    TeKeyword_Image         = 0x0000000000000004ULL,    ///< Image load events
    TeKeyword_File          = 0x0000000000000008ULL,    ///< File system events
    TeKeyword_Registry      = 0x0000000000000010ULL,    ///< Registry events
    TeKeyword_Network       = 0x0000000000000020ULL,    ///< Network events
    TeKeyword_Memory        = 0x0000000000000040ULL,    ///< Memory events

    // Security categories
    TeKeyword_Security      = 0x0000000000000080ULL,    ///< Security events
    TeKeyword_Detection     = 0x0000000000000100ULL,    ///< Detection events
    TeKeyword_Behavioral    = 0x0000000000000200ULL,    ///< Behavioral events
    TeKeyword_Threat        = 0x0000000000000400ULL,    ///< Threat events
    TeKeyword_Attack        = 0x0000000000000800ULL,    ///< Attack chain events

    // Operational categories
    TeKeyword_Performance   = 0x0000000000001000ULL,    ///< Performance metrics
    TeKeyword_Health        = 0x0000000000002000ULL,    ///< Health status
    TeKeyword_Diagnostic    = 0x0000000000004000ULL,    ///< Diagnostics
    TeKeyword_Audit         = 0x0000000000008000ULL,    ///< Audit trail

    // Special categories
    TeKeyword_SelfProtect   = 0x0000000000010000ULL,    ///< Self-protection
    TeKeyword_Evasion       = 0x0000000000020000ULL,    ///< Evasion detection
    TeKeyword_Injection     = 0x0000000000040000ULL,    ///< Injection detection
    TeKeyword_Credential    = 0x0000000000080000ULL,    ///< Credential access
    TeKeyword_Ransomware    = 0x0000000000100000ULL,    ///< Ransomware detection

    // Debug (high bit)
    TeKeyword_Debug         = 0x8000000000000000ULL,    ///< Debug events

    // Combinations
    TeKeyword_AllActivity   = 0x000000000000007FULL,
    TeKeyword_AllSecurity   = 0x0000000000000F80ULL,
    TeKeyword_AllOperational= 0x000000000000F000ULL,
    TeKeyword_All           = 0x7FFFFFFFFFFFFFFFULL
} TE_EVENT_KEYWORD;

// ============================================================================
// EVENT IDENTIFIERS
// ============================================================================

/**
 * @brief Telemetry event IDs.
 */
typedef enum _TE_EVENT_ID {
    // ========== Process Events (1-99) ==========
    TeEvent_ProcessCreate           = 1,
    TeEvent_ProcessTerminate        = 2,
    TeEvent_ProcessOpen             = 3,
    TeEvent_ProcessBlocked          = 4,
    TeEvent_ProcessSuspicious       = 5,
    TeEvent_ProcessElevated         = 6,
    TeEvent_ProcessIntegrityChange  = 7,

    // ========== Thread Events (100-199) ==========
    TeEvent_ThreadCreate            = 100,
    TeEvent_ThreadTerminate         = 101,
    TeEvent_ThreadOpen              = 102,
    TeEvent_RemoteThreadCreate      = 103,
    TeEvent_ThreadHijack            = 104,
    TeEvent_ThreadSuspicious        = 105,

    // ========== Image Events (200-299) ==========
    TeEvent_ImageLoad               = 200,
    TeEvent_ImageUnload             = 201,
    TeEvent_ImageSuspicious         = 202,
    TeEvent_ImageBlocked            = 203,
    TeEvent_ImageUnsigned           = 204,
    TeEvent_ImageTampered           = 205,

    // ========== File Events (300-399) ==========
    TeEvent_FileCreate              = 300,
    TeEvent_FileRead                = 301,
    TeEvent_FileWrite               = 302,
    TeEvent_FileDelete              = 303,
    TeEvent_FileRename              = 304,
    TeEvent_FileBlocked             = 305,
    TeEvent_FileQuarantined         = 306,
    TeEvent_FileMalware             = 307,
    TeEvent_FileADS                 = 308,
    TeEvent_FileEncrypted           = 309,

    // ========== Registry Events (400-499) ==========
    TeEvent_RegKeyCreate            = 400,
    TeEvent_RegKeyOpen              = 401,
    TeEvent_RegKeyDelete            = 402,
    TeEvent_RegValueSet             = 403,
    TeEvent_RegValueDelete          = 404,
    TeEvent_RegBlocked              = 405,
    TeEvent_RegPersistence          = 406,
    TeEvent_RegSuspicious           = 407,

    // ========== Network Events (500-599) ==========
    TeEvent_NetConnect              = 500,
    TeEvent_NetListen               = 501,
    TeEvent_NetSend                 = 502,
    TeEvent_NetReceive              = 503,
    TeEvent_NetBlocked              = 504,
    TeEvent_DnsQuery                = 505,
    TeEvent_DnsBlocked              = 506,
    TeEvent_NetC2Detected           = 507,
    TeEvent_NetExfiltration         = 508,
    TeEvent_NetBeaconing            = 509,

    // ========== Memory Events (600-699) ==========
    TeEvent_MemoryAlloc             = 600,
    TeEvent_MemoryProtect           = 601,
    TeEvent_MemoryMap               = 602,
    TeEvent_ShellcodeDetected       = 603,
    TeEvent_InjectionDetected       = 604,
    TeEvent_HollowingDetected       = 605,
    TeEvent_RWXDetected             = 606,
    TeEvent_HeapSpray               = 607,
    TeEvent_StackPivot              = 608,

    // ========== Detection Events (700-799) ==========
    TeEvent_ThreatDetected          = 700,
    TeEvent_ThreatBlocked           = 701,
    TeEvent_ThreatQuarantined       = 702,
    TeEvent_ThreatRemediated        = 703,
    TeEvent_BehaviorAlert           = 704,
    TeEvent_AttackChainStart        = 705,
    TeEvent_AttackChainUpdate       = 706,
    TeEvent_AttackChainComplete     = 707,
    TeEvent_MitreDetection          = 708,
    TeEvent_AnomalyDetected         = 709,

    // ========== Security Events (800-899) ==========
    TeEvent_TamperAttempt           = 800,
    TeEvent_EvasionAttempt          = 801,
    TeEvent_DirectSyscall           = 802,
    TeEvent_PrivilegeEscalation     = 803,
    TeEvent_CredentialAccess        = 804,
    TeEvent_TokenManipulation       = 805,
    TeEvent_CallbackRemoval         = 806,
    TeEvent_DriverTamper            = 807,
    TeEvent_ETWBlinding             = 808,
    TeEvent_AMSIBypass              = 809,

    // ========== Operational Events (900-999) ==========
    TeEvent_DriverLoaded            = 900,
    TeEvent_DriverUnloading         = 901,
    TeEvent_Heartbeat               = 902,
    TeEvent_PerformanceStats        = 903,
    TeEvent_ComponentHealth         = 904,
    TeEvent_ConfigChange            = 905,
    TeEvent_Error                   = 906,
    TeEvent_Warning                 = 907,
    TeEvent_Debug                   = 908,
    TeEvent_Audit                   = 909,

    TeEvent_Max                     = 1000
} TE_EVENT_ID;

// ============================================================================
// TELEMETRY STATE ENUMERATIONS
// ============================================================================

/**
 * @brief Telemetry subsystem state.
 */
typedef enum _TE_STATE {
    TeState_Uninitialized   = 0,
    TeState_Initializing    = 1,
    TeState_Running         = 2,
    TeState_Paused          = 3,
    TeState_Throttled       = 4,
    TeState_ShuttingDown    = 5,
    TeState_Shutdown        = 6,
    TeState_Error           = 7
} TE_STATE;

/**
 * @brief Event priority for queuing.
 */
typedef enum _TE_PRIORITY {
    TePriority_Low          = 0,
    TePriority_Normal       = 1,
    TePriority_High         = 2,
    TePriority_Critical     = 3
} TE_PRIORITY;

/**
 * @brief Throttle action when rate limit exceeded.
 */
typedef enum _TE_THROTTLE_ACTION {
    TeThrottle_None         = 0,    ///< No throttling
    TeThrottle_Sample       = 1,    ///< Sample events (1 in N)
    TeThrottle_DropLow      = 2,    ///< Drop low priority only
    TeThrottle_DropNormal   = 3,    ///< Drop normal and below
    TeThrottle_DropAll      = 4     ///< Drop all except critical
} TE_THROTTLE_ACTION;

// ============================================================================
// EVENT DATA STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Common event header for all telemetry events.
 */
typedef struct _TE_EVENT_HEADER {
    UINT32 Size;                        ///< Total event size including header
    UINT16 Version;                     ///< Event structure version
    UINT16 Flags;                       ///< Event flags
    TE_EVENT_ID EventId;                ///< Event identifier
    TE_EVENT_LEVEL Level;               ///< Event level
    UINT64 Keywords;                    ///< Event keywords
    UINT64 Timestamp;                   ///< Event timestamp (FILETIME)
    UINT64 SequenceNumber;              ///< Monotonic sequence number
    UINT32 ProcessId;                   ///< Source process ID
    UINT32 ThreadId;                    ///< Source thread ID
    UINT32 SessionId;                   ///< Session ID
    UINT32 ProcessorNumber;             ///< Processor that generated event
    UINT64 CorrelationId;               ///< Correlation ID for event chaining
    UINT64 ActivityId;                  ///< Activity ID for tracing
} TE_EVENT_HEADER, *PTE_EVENT_HEADER;

// Event header flags
#define TE_FLAG_BLOCKING            0x0001  ///< Event can block operation
#define TE_FLAG_HIGH_CONFIDENCE     0x0002  ///< High confidence detection
#define TE_FLAG_CHAIN_MEMBER        0x0004  ///< Part of attack chain
#define TE_FLAG_IOC_MATCH           0x0008  ///< Matches IOC
#define TE_FLAG_RULE_MATCH          0x0010  ///< Matches behavioral rule
#define TE_FLAG_ML_DETECTION        0x0020  ///< ML-based detection
#define TE_FLAG_URGENT              0x0040  ///< Urgent event
#define TE_FLAG_SAMPLED             0x0080  ///< Event was sampled (throttling)

/**
 * @brief Process telemetry event.
 */
typedef struct _TE_PROCESS_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 ParentProcessId;
    UINT32 CreatingProcessId;
    UINT32 CreatingThreadId;
    UINT32 ExitCode;
    UINT32 IntegrityLevel;
    UINT32 TokenElevationType;
    UINT32 ThreatScore;
    UINT32 Flags;
    UINT64 CreateTime;
    UINT64 ExitTime;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT8 ImageHash[32];                ///< SHA-256
    WCHAR ImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
    WCHAR UserSid[256];
} TE_PROCESS_EVENT, *PTE_PROCESS_EVENT;

// Process flags
#define TE_PROCESS_FLAG_ELEVATED        0x00000001
#define TE_PROCESS_FLAG_PROTECTED       0x00000002
#define TE_PROCESS_FLAG_SYSTEM          0x00000004
#define TE_PROCESS_FLAG_WOW64           0x00000008
#define TE_PROCESS_FLAG_BLOCKED         0x00000010
#define TE_PROCESS_FLAG_SUSPICIOUS      0x00000020
#define TE_PROCESS_FLAG_MICROSOFT       0x00000040
#define TE_PROCESS_FLAG_TRUSTED         0x00000080
#define TE_PROCESS_FLAG_UNSIGNED        0x00000100

/**
 * @brief Thread telemetry event.
 */
typedef struct _TE_THREAD_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 TargetProcessId;
    UINT32 TargetThreadId;
    UINT64 StartAddress;
    UINT64 Win32StartAddress;
    UINT32 ThreatScore;
    UINT32 Flags;
    WCHAR TargetProcessPath[MAX_FILE_PATH_LENGTH];
} TE_THREAD_EVENT, *PTE_THREAD_EVENT;

// Thread flags
#define TE_THREAD_FLAG_REMOTE           0x00000001
#define TE_THREAD_FLAG_SUSPENDED        0x00000002
#define TE_THREAD_FLAG_HIDDEN           0x00000004
#define TE_THREAD_FLAG_SUSPICIOUS       0x00000008
#define TE_THREAD_FLAG_BLOCKED          0x00000010

/**
 * @brief File telemetry event.
 */
typedef struct _TE_FILE_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 Operation;
    UINT32 Disposition;
    UINT32 DesiredAccess;
    UINT32 ShareAccess;
    UINT64 FileSize;
    UINT64 FileId;
    UINT32 VolumeSerial;
    UINT32 ThreatScore;
    UINT32 Verdict;
    UINT32 Flags;
    UINT8 FileHash[32];                 ///< SHA-256
    WCHAR FilePath[MAX_FILE_PATH_LENGTH];
    WCHAR ThreatName[MAX_THREAT_NAME_LENGTH];
} TE_FILE_EVENT, *PTE_FILE_EVENT;

// File flags
#define TE_FILE_FLAG_EXECUTABLE         0x00000001
#define TE_FILE_FLAG_SCRIPT             0x00000002
#define TE_FILE_FLAG_NETWORK            0x00000004
#define TE_FILE_FLAG_REMOVABLE          0x00000008
#define TE_FILE_FLAG_ENCRYPTED          0x00000010
#define TE_FILE_FLAG_ADS                0x00000020
#define TE_FILE_FLAG_BLOCKED            0x00000040
#define TE_FILE_FLAG_QUARANTINED        0x00000080

/**
 * @brief Registry telemetry event.
 */
typedef struct _TE_REGISTRY_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 Operation;
    UINT32 ValueType;
    UINT32 DataSize;
    UINT32 ThreatScore;
    UINT32 Flags;
    UINT32 Reserved;
    WCHAR KeyPath[MAX_REGISTRY_KEY_LENGTH];
    WCHAR ValueName[MAX_REGISTRY_VALUE_LENGTH];
    UINT8 ValueData[256];               ///< First 256 bytes of value
} TE_REGISTRY_EVENT, *PTE_REGISTRY_EVENT;

// Registry flags
#define TE_REG_FLAG_PERSISTENCE         0x00000001
#define TE_REG_FLAG_AUTORUN             0x00000002
#define TE_REG_FLAG_SERVICE             0x00000004
#define TE_REG_FLAG_SECURITY            0x00000008
#define TE_REG_FLAG_BLOCKED             0x00000010
#define TE_REG_FLAG_SUSPICIOUS          0x00000020

/**
 * @brief Network telemetry event.
 */
typedef struct _TE_NETWORK_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 Protocol;
    UINT32 Direction;
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT32 LocalAddressV4;
    UINT32 RemoteAddressV4;
    UINT8 LocalAddressV6[16];
    UINT8 RemoteAddressV6[16];
    UINT64 BytesSent;
    UINT64 BytesReceived;
    UINT32 ThreatScore;
    UINT32 ThreatType;
    UINT32 Flags;
    UINT32 Reserved;
    WCHAR RemoteHostname[260];
    WCHAR ProcessPath[MAX_FILE_PATH_LENGTH];
} TE_NETWORK_EVENT, *PTE_NETWORK_EVENT;

// Network flags
#define TE_NET_FLAG_BLOCKED             0x00000001
#define TE_NET_FLAG_C2                  0x00000002
#define TE_NET_FLAG_EXFILTRATION        0x00000004
#define TE_NET_FLAG_BEACONING           0x00000008
#define TE_NET_FLAG_TOR                 0x00000010
#define TE_NET_FLAG_PROXY               0x00000020
#define TE_NET_FLAG_ENCRYPTED           0x00000040
#define TE_NET_FLAG_DNS_TUNNEL          0x00000080

/**
 * @brief Memory telemetry event.
 */
typedef struct _TE_MEMORY_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 TargetProcessId;
    UINT32 Operation;
    UINT64 BaseAddress;
    UINT64 RegionSize;
    UINT32 OldProtection;
    UINT32 NewProtection;
    UINT32 AllocationType;
    UINT32 ThreatScore;
    UINT32 Flags;
    UINT32 InjectionMethod;
    UINT8 ContentHash[32];              ///< SHA-256 of content sample
    WCHAR TargetProcessPath[MAX_FILE_PATH_LENGTH];
} TE_MEMORY_EVENT, *PTE_MEMORY_EVENT;

// Memory flags
#define TE_MEM_FLAG_RWX                 0x00000001
#define TE_MEM_FLAG_UNBACKED            0x00000002
#define TE_MEM_FLAG_SHELLCODE           0x00000004
#define TE_MEM_FLAG_INJECTION           0x00000008
#define TE_MEM_FLAG_HOLLOWING           0x00000010
#define TE_MEM_FLAG_HEAP_SPRAY          0x00000020
#define TE_MEM_FLAG_ROP                 0x00000040
#define TE_MEM_FLAG_CROSS_PROCESS       0x00000080

/**
 * @brief Detection/threat telemetry event.
 */
typedef struct _TE_DETECTION_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 DetectionType;
    UINT32 DetectionSource;
    UINT32 ThreatScore;
    UINT32 Confidence;
    THREAT_SEVERITY Severity;
    UINT32 MitreTechnique;
    UINT32 MitreTactic;
    UINT32 ResponseAction;
    UINT64 ChainId;
    UINT32 ChainPosition;
    UINT32 Flags;
    UINT8 ThreatHash[32];
    WCHAR ThreatName[MAX_THREAT_NAME_LENGTH];
    WCHAR Description[512];
    WCHAR ProcessPath[MAX_FILE_PATH_LENGTH];
    WCHAR TargetPath[MAX_FILE_PATH_LENGTH];
} TE_DETECTION_EVENT, *PTE_DETECTION_EVENT;

/**
 * @brief Security alert telemetry event.
 */
typedef struct _TE_SECURITY_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 AlertType;
    UINT32 TargetComponent;
    UINT64 TargetAddress;
    UINT64 OriginalValue;
    UINT64 AttemptedValue;
    UINT32 ThreatScore;
    UINT32 ResponseAction;
    UINT32 Flags;
    UINT32 Reserved;
    WCHAR AttackerProcess[MAX_FILE_PATH_LENGTH];
    WCHAR Description[512];
} TE_SECURITY_EVENT, *PTE_SECURITY_EVENT;

/**
 * @brief Operational/diagnostic telemetry event.
 */
typedef struct _TE_OPERATIONAL_EVENT {
    TE_EVENT_HEADER Header;
    DRIVER_COMPONENT_ID ComponentId;
    COMPONENT_HEALTH_STATUS HealthStatus;
    ERROR_SEVERITY ErrorSeverity;
    UINT32 ErrorCode;
    UINT64 ContextValue1;
    UINT64 ContextValue2;
    UINT64 ContextValue3;
    WCHAR Message[MAX_ERROR_MESSAGE_LENGTH];
    CHAR FileName[64];
    CHAR FunctionName[64];
    UINT32 LineNumber;
    UINT32 Reserved;
} TE_OPERATIONAL_EVENT, *PTE_OPERATIONAL_EVENT;

#pragma pack(pop)

// ============================================================================
// TELEMETRY STATISTICS
// ============================================================================

/**
 * @brief Telemetry subsystem statistics.
 */
typedef struct _TE_STATISTICS {
    // Event counters
    volatile LONG64 EventsGenerated;
    volatile LONG64 EventsWritten;
    volatile LONG64 EventsDropped;
    volatile LONG64 EventsThrottled;
    volatile LONG64 EventsSampled;
    volatile LONG64 EventsFailed;

    // Bytes counters
    volatile LONG64 BytesGenerated;
    volatile LONG64 BytesWritten;

    // Rate tracking
    volatile LONG EventsThisSecond;
    volatile LONG PeakEventsPerSecond;
    UINT64 CurrentSecondStart;

    // Batch statistics
    volatile LONG64 BatchesWritten;
    volatile LONG64 BatchFlushes;
    volatile LONG CurrentBatchSize;
    volatile LONG MaxBatchSize;

    // Throttling statistics
    volatile LONG64 ThrottleActivations;
    volatile LONG ThrottleCurrentLevel;
    UINT64 LastThrottleTime;

    // Error tracking
    volatile LONG64 EtwWriteErrors;
    volatile LONG64 AllocationFailures;
    volatile LONG64 SequenceGaps;

    // Timing
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastEventTime;
    LARGE_INTEGER LastFlushTime;

    // Per-level counters
    volatile LONG64 EventsByLevel[6];

    // Reserved for future use
    UINT64 Reserved[8];
} TE_STATISTICS, *PTE_STATISTICS;

// ============================================================================
// TELEMETRY CONFIGURATION
// ============================================================================

/**
 * @brief Telemetry configuration.
 */
typedef struct _TE_CONFIG {
    // Enable flags
    BOOLEAN Enabled;
    BOOLEAN EnableBatching;
    BOOLEAN EnableThrottling;
    BOOLEAN EnableSampling;
    BOOLEAN EnableCorrelation;
    BOOLEAN EnableCompression;
    UINT16 Reserved1;

    // Filtering
    TE_EVENT_LEVEL MinLevel;
    UINT32 Reserved2;
    UINT64 EnabledKeywords;

    // Rate limiting
    UINT32 MaxEventsPerSecond;
    UINT32 SamplingRate;                ///< 1 in N events when throttled

    // Batching
    UINT32 MaxBatchSize;
    UINT32 MaxBatchAgeMs;

    // Throttling
    UINT32 ThrottleThreshold;           ///< Events/sec to trigger throttle
    UINT32 ThrottleRecoveryMs;          ///< Time to recover from throttle

    // Heartbeat
    UINT32 HeartbeatIntervalMs;
    UINT32 StatsIntervalMs;

    // Reserved
    UINT32 Reserved3[8];
} TE_CONFIG, *PTE_CONFIG;

// ============================================================================
// TELEMETRY PROVIDER STATE
// ============================================================================

/**
 * @brief Per-CPU event buffer.
 */
typedef struct _TE_CPU_BUFFER {
    SLIST_HEADER FreeList;              ///< Free event buffers
    SLIST_HEADER PendingList;           ///< Pending events to write
    volatile LONG PendingCount;
    volatile LONG FreeCount;
    UINT64 LastFlushTime;
    UCHAR Padding[40];                  ///< Cache line padding
} TE_CPU_BUFFER, *PTE_CPU_BUFFER;

/**
 * @brief Telemetry provider global state.
 */
typedef struct _TE_PROVIDER {
    // State
    volatile TE_STATE State;
    BOOLEAN Initialized;
    UINT8 Reserved1[3];

    // ETW registration
    REGHANDLE RegistrationHandle;
    UCHAR EnableLevel;
    UINT8 Reserved2[3];
    ULONGLONG EnableFlags;
    volatile LONG ConsumerCount;

    // Sequence tracking
    volatile LONG64 SequenceNumber;

    // Synchronization
    SHADOWSTRIKE_RWSPINLOCK StateLock;
    EX_PUSH_LOCK ConfigLock;

    // Configuration
    TE_CONFIG Config;

    // Statistics
    TE_STATISTICS Stats;

    // Memory management
    SHADOWSTRIKE_LOOKASIDE EventLookaside;
    NPAGED_LOOKASIDE_LIST SmallEventLookaside;

    // Per-CPU buffers
    PTE_CPU_BUFFER CpuBuffers;
    ULONG CpuCount;
    UINT32 Reserved3;

    // Batching
    KTIMER FlushTimer;
    KDPC FlushDpc;
    PIO_WORKITEM FlushWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG FlushPending;

    // Heartbeat
    KTIMER HeartbeatTimer;
    KDPC HeartbeatDpc;

    // Throttling
    volatile TE_THROTTLE_ACTION ThrottleAction;
    volatile LONG ThrottleSampleCounter;
    UINT64 ThrottleStartTime;

    // Activity tracking
    UINT64 LastActivityTime;
    volatile LONG ActiveOperations;

    // Reference counting for shutdown
    volatile LONG ReferenceCount;
    KEVENT ShutdownEvent;

    // Reserved
    UINT64 Reserved4[4];
} TE_PROVIDER, *PTE_PROVIDER;

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the telemetry subsystem.
 *
 * Must be called during driver initialization. Sets up ETW provider,
 * allocates buffers, and starts background threads.
 *
 * @param DeviceObject  Device object for work items
 * @param Config        Optional initial configuration (NULL for defaults)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TeInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PTE_CONFIG Config
    );

/**
 * @brief Shutdown the telemetry subsystem.
 *
 * Flushes pending events, unregisters ETW provider, and releases resources.
 * Blocks until all pending operations complete.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TeShutdown(
    VOID
    );

/**
 * @brief Check if telemetry is initialized and running.
 *
 * @return TRUE if telemetry is ready to accept events
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TeIsEnabled(
    VOID
    );

/**
 * @brief Check if specific event type is enabled.
 *
 * @param Level     Event level
 * @param Keywords  Event keywords
 *
 * @return TRUE if event would be logged
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TeIsEventEnabled(
    _In_ TE_EVENT_LEVEL Level,
    _In_ UINT64 Keywords
    );

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief Update telemetry configuration.
 *
 * @param Config    New configuration
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
TeSetConfig(
    _In_ PTE_CONFIG Config
    );

/**
 * @brief Get current telemetry configuration.
 *
 * @param Config    Receives current configuration
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeGetConfig(
    _Out_ PTE_CONFIG Config
    );

/**
 * @brief Pause telemetry event collection.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TePause(
    VOID
    );

/**
 * @brief Resume telemetry event collection.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeResume(
    VOID
    );

// ============================================================================
// EVENT LOGGING - PROCESS
// ============================================================================

/**
 * @brief Log process creation event.
 *
 * @param ProcessId         Process ID
 * @param ParentProcessId   Parent process ID
 * @param ImagePath         Process image path
 * @param CommandLine       Command line (optional)
 * @param ThreatScore       Threat score (0-1000)
 * @param Flags             Process flags
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags
    );

/**
 * @brief Log process termination event.
 *
 * @param ProcessId     Process ID
 * @param ExitCode      Exit code
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessTerminate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ExitCode
    );

/**
 * @brief Log process blocked event.
 *
 * @param ProcessId         Process ID
 * @param ParentProcessId   Parent process ID
 * @param ImagePath         Process image path
 * @param ThreatScore       Threat score
 * @param Reason            Block reason
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessBlocked(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_ PCUNICODE_STRING ImagePath,
    _In_ UINT32 ThreatScore,
    _In_opt_ PCWSTR Reason
    );

// ============================================================================
// EVENT LOGGING - THREAD
// ============================================================================

/**
 * @brief Log thread creation event.
 *
 * @param ProcessId         Process ID
 * @param ThreadId          Thread ID
 * @param StartAddress      Thread start address
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogThreadCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT64 StartAddress
    );

/**
 * @brief Log remote thread creation (injection).
 *
 * @param SourceProcessId   Source process ID
 * @param TargetProcessId   Target process ID
 * @param ThreadId          Created thread ID
 * @param StartAddress      Thread start address
 * @param ThreatScore       Threat score
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogRemoteThread(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT64 StartAddress,
    _In_ UINT32 ThreatScore
    );

// ============================================================================
// EVENT LOGGING - FILE
// ============================================================================

/**
 * @brief Log file operation event.
 *
 * @param EventId       Event ID (create, read, write, etc.)
 * @param ProcessId     Process ID
 * @param FilePath      File path
 * @param Operation     File operation type
 * @param FileSize      File size
 * @param Verdict       Scan verdict
 * @param ThreatName    Threat name (if malware)
 * @param ThreatScore   Threat score
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogFileEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ UINT32 Operation,
    _In_ UINT64 FileSize,
    _In_ UINT32 Verdict,
    _In_opt_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore
    );

/**
 * @brief Log file blocked/quarantined event.
 *
 * @param ProcessId     Process ID
 * @param FilePath      File path
 * @param ThreatName    Threat name
 * @param ThreatScore   Threat score
 * @param Quarantined   TRUE if quarantined
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogFileBlocked(
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN Quarantined
    );

// ============================================================================
// EVENT LOGGING - REGISTRY
// ============================================================================

/**
 * @brief Log registry operation event.
 *
 * @param EventId       Event ID
 * @param ProcessId     Process ID
 * @param KeyPath       Registry key path
 * @param ValueName     Value name (optional)
 * @param ValueType     Value type
 * @param ValueData     Value data (optional)
 * @param DataSize      Data size
 * @param ThreatScore   Threat score
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogRegistryEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ UINT32 ValueType,
    _In_reads_bytes_opt_(DataSize) PVOID ValueData,
    _In_ UINT32 DataSize,
    _In_ UINT32 ThreatScore
    );

// ============================================================================
// EVENT LOGGING - NETWORK
// ============================================================================

/**
 * @brief Log network connection event.
 *
 * @param EventId       Event ID
 * @param Event         Pre-filled network event structure
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogNetworkEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ PTE_NETWORK_EVENT Event
    );

/**
 * @brief Log DNS query event.
 *
 * @param ProcessId     Process ID
 * @param QueryName     DNS query name
 * @param QueryType     Query type
 * @param Blocked       TRUE if blocked
 * @param ThreatScore   Threat score
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogDnsQuery(
    _In_ UINT32 ProcessId,
    _In_ PCWSTR QueryName,
    _In_ UINT16 QueryType,
    _In_ BOOLEAN Blocked,
    _In_ UINT32 ThreatScore
    );

// ============================================================================
// EVENT LOGGING - MEMORY
// ============================================================================

/**
 * @brief Log memory operation event.
 *
 * @param EventId           Event ID
 * @param SourceProcessId   Source process ID
 * @param TargetProcessId   Target process ID
 * @param BaseAddress       Memory base address
 * @param RegionSize        Region size
 * @param Protection        Memory protection
 * @param ThreatScore       Threat score
 * @param Flags             Memory flags
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogMemoryEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 RegionSize,
    _In_ UINT32 Protection,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags
    );

/**
 * @brief Log injection detection event.
 *
 * @param SourceProcessId   Injector process ID
 * @param TargetProcessId   Target process ID
 * @param InjectionMethod   Detected injection method
 * @param TargetAddress     Injection target address
 * @param Size              Injection size
 * @param ThreatScore       Threat score
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogInjection(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT32 InjectionMethod,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 Size,
    _In_ UINT32 ThreatScore
    );

// ============================================================================
// EVENT LOGGING - DETECTION
// ============================================================================

/**
 * @brief Log threat detection event.
 *
 * @param ProcessId         Process ID
 * @param ThreatName        Threat name
 * @param ThreatScore       Threat score
 * @param Severity          Threat severity
 * @param MitreTechnique    MITRE ATT&CK technique ID
 * @param Description       Detection description
 * @param ResponseAction    Response action taken
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogThreatDetection(
    _In_ UINT32 ProcessId,
    _In_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore,
    _In_ THREAT_SEVERITY Severity,
    _In_ UINT32 MitreTechnique,
    _In_opt_ PCWSTR Description,
    _In_ UINT32 ResponseAction
    );

/**
 * @brief Log behavioral alert event.
 *
 * @param ProcessId         Process ID
 * @param BehaviorType      Behavior type
 * @param Category          Behavior category
 * @param ThreatScore       Threat score
 * @param ChainId           Attack chain ID (0 if none)
 * @param Description       Alert description
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogBehaviorAlert(
    _In_ UINT32 ProcessId,
    _In_ BEHAVIOR_EVENT_TYPE BehaviorType,
    _In_ BEHAVIOR_EVENT_CATEGORY Category,
    _In_ UINT32 ThreatScore,
    _In_ UINT64 ChainId,
    _In_opt_ PCWSTR Description
    );

/**
 * @brief Log attack chain event.
 *
 * @param ChainId           Chain ID
 * @param Stage             Attack stage
 * @param ProcessId         Current process ID
 * @param EventType         Behavior event type
 * @param ThreatScore       Cumulative threat score
 * @param MitreTechnique    MITRE technique ID
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogAttackChain(
    _In_ UINT64 ChainId,
    _In_ ATTACK_CHAIN_STAGE Stage,
    _In_ UINT32 ProcessId,
    _In_ BEHAVIOR_EVENT_TYPE EventType,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 MitreTechnique
    );

// ============================================================================
// EVENT LOGGING - SECURITY
// ============================================================================

/**
 * @brief Log tamper attempt event.
 *
 * @param TamperType        Type of tamper attempt
 * @param ProcessId         Attacker process ID
 * @param TargetComponent   Targeted component
 * @param TargetAddress     Target address (if applicable)
 * @param Blocked           TRUE if blocked
 * @param Description       Description
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogTamperAttempt(
    _In_ TAMPER_ATTEMPT_TYPE TamperType,
    _In_ UINT32 ProcessId,
    _In_ DRIVER_COMPONENT_ID TargetComponent,
    _In_ UINT64 TargetAddress,
    _In_ BOOLEAN Blocked,
    _In_opt_ PCWSTR Description
    );

/**
 * @brief Log evasion attempt event.
 *
 * @param EvasionType       Evasion technique
 * @param ProcessId         Process ID
 * @param TargetModule      Target module name
 * @param TargetFunction    Target function name
 * @param ThreatScore       Threat score
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogEvasionAttempt(
    _In_ EVASION_TECHNIQUE EvasionType,
    _In_ UINT32 ProcessId,
    _In_opt_ PCWSTR TargetModule,
    _In_opt_ PCSTR TargetFunction,
    _In_ UINT32 ThreatScore
    );

/**
 * @brief Log credential access attempt.
 *
 * @param ProcessId             Attacker process ID
 * @param TargetProcessId       Target process ID (e.g., lsass)
 * @param AccessType            Credential access type
 * @param AccessMask            Requested access mask
 * @param ThreatScore           Threat score
 * @param Blocked               TRUE if blocked
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogCredentialAccess(
    _In_ UINT32 ProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ CREDENTIAL_ACCESS_TYPE AccessType,
    _In_ UINT64 AccessMask,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN Blocked
    );

// ============================================================================
// EVENT LOGGING - OPERATIONAL
// ============================================================================

/**
 * @brief Log driver operational event.
 *
 * @param EventId       Event ID
 * @param Level         Event level
 * @param ComponentId   Source component
 * @param Message       Event message
 * @param ErrorCode     Error code (0 if none)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogOperational(
    _In_ TE_EVENT_ID EventId,
    _In_ TE_EVENT_LEVEL Level,
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ PCWSTR Message,
    _In_ UINT32 ErrorCode
    );

/**
 * @brief Log error event with source location.
 *
 * @param ComponentId   Source component
 * @param ErrorCode     Error code (NTSTATUS)
 * @param Severity      Error severity
 * @param FileName      Source file name
 * @param FunctionName  Function name
 * @param LineNumber    Line number
 * @param Message       Error message
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogError(
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ NTSTATUS ErrorCode,
    _In_ ERROR_SEVERITY Severity,
    _In_ PCSTR FileName,
    _In_ PCSTR FunctionName,
    _In_ UINT32 LineNumber,
    _In_ PCWSTR Message
    );

/**
 * @brief Log component health status change.
 *
 * @param ComponentId   Component ID
 * @param NewStatus     New health status
 * @param OldStatus     Previous health status
 * @param ErrorCode     Associated error code
 * @param Message       Status message
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogComponentHealth(
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ COMPONENT_HEALTH_STATUS NewStatus,
    _In_ COMPONENT_HEALTH_STATUS OldStatus,
    _In_ UINT32 ErrorCode,
    _In_opt_ PCWSTR Message
    );

/**
 * @brief Log performance statistics.
 *
 * @param Stats     Performance statistics structure
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogPerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    );

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get telemetry statistics.
 *
 * @param Stats     Receives statistics
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeGetStatistics(
    _Out_ PTE_STATISTICS Stats
    );

/**
 * @brief Reset telemetry statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeResetStatistics(
    VOID
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Flush pending telemetry events.
 *
 * Forces immediate write of all buffered events.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeFlush(
    VOID
    );

/**
 * @brief Generate new correlation ID.
 *
 * @return Unique correlation ID
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
TeGenerateCorrelationId(
    VOID
    );

/**
 * @brief Get current sequence number.
 *
 * @return Current sequence number
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
TeGetSequenceNumber(
    VOID
    );

/**
 * @brief Get telemetry subsystem state.
 *
 * @return Current state
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
TE_STATE
TeGetState(
    VOID
    );

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

/**
 * @brief Log error with automatic source location.
 */
#define TE_LOG_ERROR(comp, status, sev, msg) \
    TeLogError(comp, status, sev, __FILE__, __FUNCTION__, __LINE__, msg)

/**
 * @brief Log warning with automatic source location.
 */
#define TE_LOG_WARNING(comp, msg) \
    TeLogOperational(TeEvent_Warning, TeLevel_Warning, comp, msg, 0)

/**
 * @brief Log info message.
 */
#define TE_LOG_INFO(comp, msg) \
    TeLogOperational(TeEvent_Debug, TeLevel_Informational, comp, msg, 0)

/**
 * @brief Log debug message (verbose only).
 */
#define TE_LOG_DEBUG(comp, msg) \
    do { \
        if (TeIsEventEnabled(TeLevel_Verbose, TeKeyword_Debug)) { \
            TeLogOperational(TeEvent_Debug, TeLevel_Verbose, comp, msg, 0); \
        } \
    } while(0)

/**
 * @brief Check if process events are enabled.
 */
#define TE_PROCESS_ENABLED() \
    TeIsEventEnabled(TeLevel_Informational, TeKeyword_Process)

/**
 * @brief Check if file events are enabled.
 */
#define TE_FILE_ENABLED() \
    TeIsEventEnabled(TeLevel_Informational, TeKeyword_File)

/**
 * @brief Check if threat events are enabled.
 */
#define TE_THREAT_ENABLED() \
    TeIsEventEnabled(TeLevel_Warning, TeKeyword_Threat)

/**
 * @brief Check if security events are enabled.
 */
#define TE_SECURITY_ENABLED() \
    TeIsEventEnabled(TeLevel_Warning, TeKeyword_Security)

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_TELEMETRY_EVENTS_H_
