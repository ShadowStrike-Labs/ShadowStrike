/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ETW TELEMETRY ENGINE
 * ============================================================================
 *
 * @file TelemetryEvents.h
 * @brief Enterprise-grade ETW telemetry for kernel-mode EDR operations.
 *
 * Provides high-performance telemetry streaming with:
 * - Lookaside-based event allocation (zero stack overflow risk)
 * - Synchronous ETW event emission with atomic state management
 * - Adaptive rate limiting and throttling
 * - SIEM-ready event schemas (ECS compatible)
 * - Attack chain correlation and MITRE ATT&CK mapping
 * - Real-time behavioral telemetry streaming
 * - Configurable verbosity levels per category
 * - Memory-efficient lookaside-based event allocation
 * - Graceful degradation under memory pressure
 *
 * Security Guarantees:
 * - No sensitive data logged (PII/credentials filtered)
 * - Tamper-evident event sequencing
 * - Rate limiting prevents DoS via event flooding
 * - All events include unique correlation IDs
 *
 * Performance Guarantees:
 * - Lookaside lists for zero-allocation hot path
 * - Adaptive throttling preserves system stability
 * - Bounded string operations prevent runaway scans
 *
 * MITRE ATT&CK Coverage:
 * - Full technique ID embedding in events
 * - Kill chain stage tracking
 * - Attack chain correlation across events
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
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
#include <ntstrsafe.h>
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
 *
 * EXTERN_C declaration here; actual definition in TelemetryEvents.c
 * via INITGUID + DEFINE_GUID. Placing DEFINE_GUID in a header causes
 * multiple-definition linker errors when included by more than one TU.
 */
EXTERN_C const GUID SHADOWSTRIKE_TELEMETRY_PROVIDER_GUID;

/**
 * @brief Provider name for ETW registration.
 */
#define TE_PROVIDER_NAME            L"ShadowStrike-Telemetry-Provider"

// ============================================================================
// POOL TAGS
// ============================================================================

#define TE_POOL_TAG                 'ETle'  // "elTE" in debugger
#define TE_EVENT_TAG                'ETve'  // "evTE" in debugger
#define TE_BATCH_TAG                'ETba'  // "abTE" in debugger
#define TE_CONTEXT_TAG              'ETcx'  // "xcTE" in debugger
#define TE_STRING_TAG               'ETst'  // "stTE" in debugger

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
 * @brief Maximum string length in events (characters).
 * Used as a safety bound for unbounded PCWSTR inputs.
 */
#define TE_MAX_STRING_LENGTH                2048

/**
 * @brief Maximum command line length for telemetry events (characters).
 * Capped to keep TE_PROCESS_EVENT within TE_MAX_EVENT_DATA_SIZE.
 * Full command lines exceeding this are truncated in telemetry.
 */
#define TE_MAX_COMMAND_LINE_CHARS           4096

/**
 * @brief Maximum event data size.
 * Must be >= sizeof(largest event struct). Validated by C_ASSERT below.
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
 * @brief Maximum number of ETW event levels tracked in statistics.
 * Levels range from 1 (Critical) to 5 (Verbose). Index 0 is unused.
 */
#define TE_MAX_EVENT_LEVELS                 6

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
 *
 * C enums are int-sized, but ETW keywords are UINT64. Use #define constants
 * with a UINT64 typedef to support the full 64-bit bitmask range.
 */
typedef UINT64 TE_EVENT_KEYWORD;

#define TeKeyword_None              0x0000000000000000ULL

// Activity categories
#define TeKeyword_Process           0x0000000000000001ULL
#define TeKeyword_Thread            0x0000000000000002ULL
#define TeKeyword_Image             0x0000000000000004ULL
#define TeKeyword_File              0x0000000000000008ULL
#define TeKeyword_Registry          0x0000000000000010ULL
#define TeKeyword_Network           0x0000000000000020ULL
#define TeKeyword_Memory            0x0000000000000040ULL

// Security categories
#define TeKeyword_Security          0x0000000000000080ULL
#define TeKeyword_Detection         0x0000000000000100ULL
#define TeKeyword_Behavioral        0x0000000000000200ULL
#define TeKeyword_Threat            0x0000000000000400ULL
#define TeKeyword_Attack            0x0000000000000800ULL

// Operational categories
#define TeKeyword_Performance       0x0000000000001000ULL
#define TeKeyword_Health            0x0000000000002000ULL
#define TeKeyword_Diagnostic        0x0000000000004000ULL
#define TeKeyword_Audit             0x0000000000008000ULL

// Special categories
#define TeKeyword_SelfProtect       0x0000000000010000ULL
#define TeKeyword_Evasion           0x0000000000020000ULL
#define TeKeyword_Injection         0x0000000000040000ULL
#define TeKeyword_Credential        0x0000000000080000ULL
#define TeKeyword_Ransomware        0x0000000000100000ULL

// Debug (high bit)
#define TeKeyword_Debug             0x8000000000000000ULL

// Combinations
#define TeKeyword_AllActivity       0x000000000000007FULL
#define TeKeyword_AllSecurity       0x0000000000000F80ULL
#define TeKeyword_AllOperational    0x000000000000F000ULL
#define TeKeyword_All               0x7FFFFFFFFFFFFFFFULL

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
// EVENT ID RANGE VALIDATION HELPERS
// ============================================================================

#define TE_IS_PROCESS_EVENT(id)     ((id) >= 1 && (id) <= 99)
#define TE_IS_THREAD_EVENT(id)      ((id) >= 100 && (id) <= 199)
#define TE_IS_IMAGE_EVENT(id)       ((id) >= 200 && (id) <= 299)
#define TE_IS_FILE_EVENT(id)        ((id) >= 300 && (id) <= 399)
#define TE_IS_REGISTRY_EVENT(id)    ((id) >= 400 && (id) <= 499)
#define TE_IS_NETWORK_EVENT(id)     ((id) >= 500 && (id) <= 599)
#define TE_IS_MEMORY_EVENT(id)      ((id) >= 600 && (id) <= 699)
#define TE_IS_DETECTION_EVENT(id)   ((id) >= 700 && (id) <= 799)
#define TE_IS_SECURITY_EVENT(id)    ((id) >= 800 && (id) <= 899)
#define TE_IS_OPERATIONAL_EVENT(id) ((id) >= 900 && (id) <= 999)
#define TE_IS_VALID_EVENT(id)       ((id) >= 1 && (id) < TeEvent_Max)

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

/*
 * NOTE: Event structures use natural alignment for internal use.
 * The ETW wire format is the raw struct written via EtwWrite.
 * Natural alignment ensures interlocked and atomic operations
 * on 64-bit fields function correctly on all architectures.
 */

/**
 * @brief Common event header for all telemetry events.
 *
 * Uses fixed-width integer types (not enums) to guarantee stable wire format
 * regardless of compiler enum size settings.
 */
typedef struct _TE_EVENT_HEADER {
    UINT32 Size;                        ///< Total event size including header
    UINT16 Version;                     ///< Event structure version
    UINT16 Flags;                       ///< Event flags
    UINT32 EventId;                     ///< Event identifier (TE_EVENT_ID)
    UINT32 Level;                       ///< Event level (TE_EVENT_LEVEL)
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

C_ASSERT(sizeof(TE_EVENT_HEADER) == 72);

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
 *
 * CommandLine is capped at TE_MAX_COMMAND_LINE_CHARS to stay within
 * TE_MAX_EVENT_DATA_SIZE. Full command lines are truncated with
 * null-termination preserved.
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
    WCHAR CommandLine[TE_MAX_COMMAND_LINE_CHARS];
    WCHAR UserSid[256];
    WCHAR BlockReason[256];             ///< Reason for block (if blocked)
} TE_PROCESS_EVENT, *PTE_PROCESS_EVENT;

C_ASSERT(sizeof(TE_PROCESS_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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

C_ASSERT(sizeof(TE_THREAD_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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

C_ASSERT(sizeof(TE_FILE_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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

C_ASSERT(sizeof(TE_REGISTRY_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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
    UINT16 DnsQueryType;                ///< DNS query type (A=1, AAAA=28, TXT=16, etc.)
    UINT16 Reserved;
    WCHAR RemoteHostname[260];
    WCHAR ProcessPath[MAX_FILE_PATH_LENGTH];
} TE_NETWORK_EVENT, *PTE_NETWORK_EVENT;

C_ASSERT(sizeof(TE_NETWORK_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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

C_ASSERT(sizeof(TE_MEMORY_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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

C_ASSERT(sizeof(TE_DETECTION_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

/**
 * @brief Security alert telemetry event.
 */
typedef struct _TE_SECURITY_EVENT {
    TE_EVENT_HEADER Header;
    UINT32 AlertType;
    UINT32 TargetComponent;
    UINT32 TargetProcessId;             ///< Target process (e.g., credential access target)
    UINT32 Reserved;
    UINT64 TargetAddress;
    UINT64 OriginalValue;
    UINT64 AttemptedValue;
    UINT32 ThreatScore;
    UINT32 ResponseAction;
    UINT32 Flags;
    UINT32 Reserved2;
    WCHAR AttackerProcess[MAX_FILE_PATH_LENGTH];
    WCHAR Description[512];
} TE_SECURITY_EVENT, *PTE_SECURITY_EVENT;

C_ASSERT(sizeof(TE_SECURITY_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

/**
 * @brief Operational/diagnostic telemetry event.
 */
typedef struct _TE_OPERATIONAL_EVENT {
    TE_EVENT_HEADER Header;
    DRIVER_COMPONENT_ID ComponentId;
    COMPONENT_HEALTH_STATUS HealthStatus;
    TELEMETRY_ERROR_SEVERITY ErrorSeverity;
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

C_ASSERT(sizeof(TE_OPERATIONAL_EVENT) <= TE_MAX_EVENT_DATA_SIZE);

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
    volatile LONG64 CurrentSecondStart;

    // Batch statistics
    volatile LONG64 BatchesWritten;
    volatile LONG64 BatchFlushes;
    volatile LONG CurrentBatchSize;
    volatile LONG MaxBatchSize;

    // Throttling statistics
    volatile LONG64 ThrottleActivations;
    volatile LONG ThrottleCurrentLevel;
    volatile LONG64 LastThrottleTime;

    // Error tracking
    volatile LONG64 EtwWriteErrors;
    volatile LONG64 AllocationFailures;
    volatile LONG64 SequenceGaps;

    // Timing (use LONG64 for interlocked access)
    volatile LONG64 StartTime;
    volatile LONG64 LastEventTime;
    volatile LONG64 LastFlushTime;

    // Per-level counters (indexed by TE_EVENT_LEVEL, 0=unused, 1-5=levels)
    volatile LONG64 EventsByLevel[TE_MAX_EVENT_LEVELS];

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
    //
    // MaxVerbosity: Maximum ETW level to log. Events with a level numerically
    // greater than this value are filtered. ETW levels: 1=Critical, 2=Error,
    // 3=Warning, 4=Informational, 5=Verbose. Setting to 4 (Informational)
    // filters out Verbose events.
    //
    TE_EVENT_LEVEL MaxVerbosity;
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
 * @brief Telemetry provider global state.
 */
typedef struct _TE_PROVIDER {
    // State (atomically managed via InterlockedCompareExchange)
    volatile LONG State;
    UINT8 Reserved0[4];

    // ETW registration
    REGHANDLE RegistrationHandle;
    volatile UCHAR EnableLevel;
    UINT8 Reserved2[3];
    volatile ULONGLONG EnableFlags;
    volatile LONG ConsumerCount;
    volatile LONG EtwEnabled;

    // Sequence tracking
    volatile LONG64 SequenceNumber;

    // Synchronization
    SHADOWSTRIKE_RWSPINLOCK ConfigLock;

    // Configuration (protected by ConfigLock)
    TE_CONFIG Config;

    // Statistics
    TE_STATISTICS Stats;

    // Memory management
    SHADOWSTRIKE_LOOKASIDE EventLookaside;

    // Batching/Flush
    KTIMER FlushTimer;
    KDPC FlushDpc;
    PIO_WORKITEM FlushWorkItem;
    PDEVICE_OBJECT DeviceObject;
    volatile LONG FlushPending;

    // Heartbeat
    KTIMER HeartbeatTimer;
    KDPC HeartbeatDpc;

    // Throttling
    volatile LONG ThrottleAction;
    volatile LONG ThrottleSampleCounter;
    volatile LONG64 ThrottleStartTime;

    //
    // Cached throttle config for lock-free hot-path reads.
    // Updated atomically under ConfigLock whenever config changes.
    //
    volatile LONG CachedEnableThrottling;
    volatile LONG CachedSamplingRate;
    volatile LONG CachedThrottleThreshold;
    volatile LONG CachedThrottleRecoveryMs;

    // Activity tracking
    volatile LONG64 LastActivityTime;
    volatile LONG ActiveOperations;

    // Reference counting for shutdown
    volatile LONG ReferenceCount;
    KEVENT ShutdownEvent;

    // Heartbeat running state (for pause/resume)
    volatile LONG HeartbeatRunning;

    // Statistics snapshot lock
    SHADOWSTRIKE_RWSPINLOCK StatsLock;

    // Reserved
    UINT64 Reserved4[4];
} TE_PROVIDER, *PTE_PROVIDER;

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the telemetry subsystem.
 *
 * Must be called during driver initialization at PASSIVE_LEVEL.
 * Uses atomic state transition to prevent double-initialization.
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
 * Cancels timers, waits for DPCs to drain, unregisters ETW provider,
 * and releases all resources. Blocks until all pending operations complete.
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
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
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
 * Uses atomic state transition. Will not override a shutdown in progress.
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
 * Uses atomic state transition. Only resumes from Paused state.
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

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogProcessTerminate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ExitCode
    );

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

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogThreadCreate(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT64 StartAddress
    );

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

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogNetworkEvent(
    _In_ TE_EVENT_ID EventId,
    _In_ PTE_NETWORK_EVENT Event
    );

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

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogEvasionAttempt(
    _In_ EVASION_TECHNIQUE EvasionType,
    _In_ UINT32 ProcessId,
    _In_opt_ PCWSTR TargetModule,
    _In_opt_ PCSTR TargetFunction,
    _In_ UINT32 ThreatScore
    );

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

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogOperational(
    _In_ TE_EVENT_ID EventId,
    _In_ TE_EVENT_LEVEL Level,
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ PCWSTR Message,
    _In_ UINT32 ErrorCode
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogError(
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ NTSTATUS ErrorCode,
    _In_ TELEMETRY_ERROR_SEVERITY Severity,
    _In_ PCSTR FileName,
    _In_ PCSTR FunctionName,
    _In_ UINT32 LineNumber,
    _In_ PCWSTR Message
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogComponentHealth(
    _In_ DRIVER_COMPONENT_ID ComponentId,
    _In_ COMPONENT_HEALTH_STATUS NewStatus,
    _In_ COMPONENT_HEALTH_STATUS OldStatus,
    _In_ UINT32 ErrorCode,
    _In_opt_ PCWSTR Message
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeLogPerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    );

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
TeGetStatistics(
    _Out_ PTE_STATISTICS Stats
    );

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
 * Currently events are written synchronously, so this updates
 * the last flush timestamp. Present for API completeness.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TeFlush(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
TeGenerateCorrelationId(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
TeGetSequenceNumber(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
TE_STATE
TeGetState(
    VOID
    );

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

#define TE_LOG_ERROR(comp, status, sev, msg) \
    TeLogError(comp, status, sev, __FILE__, __FUNCTION__, __LINE__, msg)

#define TE_LOG_WARNING(comp, msg) \
    TeLogOperational(TeEvent_Warning, TeLevel_Warning, comp, msg, 0)

#define TE_LOG_INFO(comp, msg) \
    TeLogOperational(TeEvent_Debug, TeLevel_Informational, comp, msg, 0)

#define TE_LOG_DEBUG(comp, msg) \
    do { \
        if (TeIsEventEnabled(TeLevel_Verbose, TeKeyword_Debug)) { \
            TeLogOperational(TeEvent_Debug, TeLevel_Verbose, comp, msg, 0); \
        } \
    } while(0)

#define TE_PROCESS_ENABLED() \
    TeIsEventEnabled(TeLevel_Informational, TeKeyword_Process)

#define TE_FILE_ENABLED() \
    TeIsEventEnabled(TeLevel_Informational, TeKeyword_File)

#define TE_THREAT_ENABLED() \
    TeIsEventEnabled(TeLevel_Warning, TeKeyword_Threat)

#define TE_SECURITY_ENABLED() \
    TeIsEventEnabled(TeLevel_Warning, TeKeyword_Security)

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_TELEMETRY_EVENTS_H_
