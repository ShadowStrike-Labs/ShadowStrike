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
 * ShadowStrike NGAV - ENTERPRISE SCAN BRIDGE ENGINE
 * ============================================================================
 *
 * @file ScanBridge.h
 * @brief Enterprise-grade scan bridge for kernel-to-usermode communication.
 *
 * Provides CrowdStrike Falcon-class scan coordination with:
 * - Synchronous scan requests with configurable timeouts
 * - Asynchronous fire-and-forget notifications
 * - Multi-priority message queuing
 * - Connection state management
 * - Message correlation and tracking
 * - Automatic retry with exponential backoff
 * - Circuit breaker pattern for resilience
 * - Per-message statistics and latency tracking
 * - Memory-efficient buffer pooling
 * - Safe message serialization
 *
 * Security Guarantees:
 * - All message buffers are validated before use
 * - Integer overflow protection on all size calculations
 * - Safe string handling with length limits
 * - Exception handling for user-mode data access
 * - Proper cleanup on all error paths
 * - Proper buffer tracking for lookaside vs pool allocations
 *
 * Performance Optimizations:
 * - Lookaside list for frequent allocations
 * - Zero-copy where possible
 * - Batched notifications for high-volume events
 * - IRQL-aware operation selection
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (process/thread notifications)
 * - T1547: Boot/Logon Autostart (registry monitoring)
 * - T1059: Command and Scripting Interpreter (image load)
 * - T1036: Masquerading (file scan verdicts)
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_SCAN_BRIDGE_H_
#define _SHADOWSTRIKE_SCAN_BRIDGE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include "../../Shared/MessageProtocol.h"
#include "../../Shared/VerdictTypes.h"
#include "../../Shared/MessageTypes.h"

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for scan bridge allocations
 */
#define SB_POOL_TAG             'bSsS'

/**
 * @brief Pool tag for message buffers
 */
#define SB_MESSAGE_TAG          'mSsS'

/**
 * @brief Pool tag for request tracking
 */
#define SB_REQUEST_TAG          'rSsS'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum message size (64KB)
 */
#define SHADOWSTRIKE_MAX_MESSAGE_SIZE       (64 * 1024)

/**
 * @brief Default scan timeout in milliseconds
 */
#define SB_DEFAULT_SCAN_TIMEOUT_MS          30000

/**
 * @brief Minimum scan timeout
 */
#define SB_MIN_SCAN_TIMEOUT_MS              100

/**
 * @brief Maximum scan timeout (5 minutes)
 */
#define SB_MAX_SCAN_TIMEOUT_MS              300000

/**
 * @brief Maximum retry count for failed sends
 */
#define SB_MAX_RETRY_COUNT                  3

/**
 * @brief Retry delay base (milliseconds)
 */
#define SB_RETRY_DELAY_BASE_MS              100

/**
 * @brief Maximum retry delay (milliseconds) - cap for exponential backoff
 */
#define SB_MAX_RETRY_DELAY_MS               5000

/**
 * @brief Maximum path length in scan requests
 */
#define SB_MAX_PATH_LENGTH                  (32 * 1024)

/**
 * @brief Maximum process name length
 */
#define SB_MAX_PROCESS_NAME_LENGTH          520

/**
 * @brief Maximum registry data size to capture
 */
#define SB_MAX_REGISTRY_DATA_SIZE           4096

/**
 * @brief Circuit breaker threshold (failures before open)
 */
#define SB_CIRCUIT_BREAKER_THRESHOLD        5

/**
 * @brief Circuit breaker recovery time (milliseconds)
 */
#define SB_CIRCUIT_BREAKER_RECOVERY_MS      30000

/**
 * @brief Message lookaside list depth
 */
#define SB_LOOKASIDE_DEPTH                  256

/**
 * @brief Standard message buffer size for lookaside
 */
#define SB_STANDARD_BUFFER_SIZE             4096

/**
 * @brief Large message buffer size for lookaside
 */
#define SB_LARGE_BUFFER_SIZE                SHADOWSTRIKE_MAX_MESSAGE_SIZE

// ============================================================================
// MESSAGE FLAGS
// ============================================================================

/**
 * @brief Message header flag: High priority
 */
#define SB_MSG_FLAG_HIGH_PRIORITY           0x0001

/**
 * @brief Message header flag: Bypass cache
 */
#define SB_MSG_FLAG_BYPASS_CACHE            0x0002

/**
 * @brief Message header flag: Requires reply
 */
#define SB_MSG_FLAG_REQUIRES_REPLY          0x0004

/**
 * @brief Verdict flag: Threat detected
 */
#define SB_VERDICT_FLAG_THREAT_DETECTED     0x0001

/**
 * @brief Verdict flag: Result from cache
 */
#define SB_VERDICT_FLAG_FROM_CACHE          0x0002

// ============================================================================
// BUFFER ALLOCATION SOURCE TRACKING
// ============================================================================

/**
 * @brief Buffer source: Direct pool allocation
 */
#define SB_BUFFER_SOURCE_POOL               0

/**
 * @brief Buffer source: Standard lookaside list
 */
#define SB_BUFFER_SOURCE_STANDARD_LOOKASIDE 1

/**
 * @brief Buffer source: Large lookaside list
 */
#define SB_BUFFER_SOURCE_LARGE_LOOKASIDE    2

/**
 * @brief Buffer header magic value for validation
 */
#define SB_BUFFER_HEADER_MAGIC              0x53424844  // 'SBHD'

// ============================================================================
// ERROR CODES
// ============================================================================

//
// Use canonical error codes from ErrorCodes.h when available.
// ScanBridge-specific error codes use the 0xE00000xx range.
//
#include "../../Shared/ErrorCodes.h"

#ifndef SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED
#define SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED   ((NTSTATUS)0xE0000001L)
#endif

#ifndef SHADOWSTRIKE_ERROR_SCAN_TIMEOUT
#define SHADOWSTRIKE_ERROR_SCAN_TIMEOUT         ((NTSTATUS)0xE0000002L)
#endif

/**
 * @brief Circuit breaker open error
 */
#define SHADOWSTRIKE_ERROR_CIRCUIT_OPEN         ((NTSTATUS)0xE0000003L)

/**
 * @brief Message too large error
 */
#define SHADOWSTRIKE_ERROR_MESSAGE_TOO_LARGE    ((NTSTATUS)0xE0000004L)

/**
 * @brief Integer overflow error
 */
#define SHADOWSTRIKE_ERROR_INTEGER_OVERFLOW     ((NTSTATUS)0xE0000005L)

// ============================================================================
// ENUMERATIONS
// ============================================================================

//
// SHADOWSTRIKE_ACCESS_TYPE and SHADOWSTRIKE_FILE_ACCESS_TYPE are defined
// in SharedDefs.h (included via MessageProtocol.h).
//

/**
 * @brief Message priority levels
 */
typedef enum _SB_MESSAGE_PRIORITY {
    SbPriorityLow = 0,
    SbPriorityNormal = 1,
    SbPriorityHigh = 2,
    SbPriorityCritical = 3
} SB_MESSAGE_PRIORITY;

/**
 * @brief Scan request flags
 */
typedef enum _SB_SCAN_FLAGS {
    SbScanFlagNone              = 0x00000000,
    SbScanFlagSynchronous       = 0x00000001,   // Wait for verdict
    SbScanFlagCacheable         = 0x00000002,   // Result can be cached
    SbScanFlagHighPriority      = 0x00000004,   // High priority scan
    SbScanFlagExecuteContext    = 0x00000008,   // Execution context scan
    SbScanFlagNetworkFile       = 0x00000010,   // File is on network
    SbScanFlagRemovableMedia    = 0x00000020,   // File is on removable media
    SbScanFlagSystemFile        = 0x00000040,   // System file
    SbScanFlagBypassCache       = 0x00000080    // Bypass cache, force rescan
} SB_SCAN_FLAGS;

/**
 * @brief Circuit breaker state
 */
typedef enum _SB_CIRCUIT_STATE {
    SbCircuitClosed = 0,        // Normal operation
    SbCircuitOpen = 1,          // Failing, reject requests
    SbCircuitHalfOpen = 2       // Testing recovery
} SB_CIRCUIT_STATE;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Buffer header for tracking allocation source
 *
 * Prepended to every buffer allocation to track where the buffer
 * came from, enabling correct deallocation.
 */
typedef struct _SB_BUFFER_HEADER {
    ULONG Magic;                // SB_BUFFER_HEADER_MAGIC
    ULONG Source;               // SB_BUFFER_SOURCE_*
    ULONG RequestedSize;        // Original requested size
    ULONG AllocatedSize;        // Actual allocated size
} SB_BUFFER_HEADER, *PSB_BUFFER_HEADER;

/**
 * @brief Extended scan request options
 */
typedef struct _SB_SCAN_OPTIONS {
    ULONG TimeoutMs;            // Scan timeout (0 = default)
    SB_SCAN_FLAGS Flags;        // Scan flags
    SB_MESSAGE_PRIORITY Priority; // Message priority
    ULONG MaxRetries;           // Maximum retry count (0 = default)
    PVOID UserContext;          // Caller context (returned in result)
} SB_SCAN_OPTIONS, *PSB_SCAN_OPTIONS;

/**
 * @brief Extended scan result
 */
typedef struct _SB_SCAN_RESULT {
    SHADOWSTRIKE_SCAN_VERDICT Verdict;  // Scan verdict
    NTSTATUS Status;                    // Operation status
    ULONG ThreatScore;                  // Threat score (0-100)
    BOOLEAN ThreatDetected;             // Threat was detected
    BOOLEAN FromCache;                  // Result was from cache
    ULONG LatencyMs;                    // Scan latency in milliseconds
    WCHAR ThreatName[128];              // Threat name if detected
    PVOID UserContext;                  // Caller context from options
} SB_SCAN_RESULT, *PSB_SCAN_RESULT;

/**
 * @brief Scan bridge statistics
 */
typedef struct _SB_STATISTICS {
    //
    // Request counts
    //
    volatile LONG64 TotalScanRequests;
    volatile LONG64 SuccessfulScans;
    volatile LONG64 FailedScans;
    volatile LONG64 TimeoutScans;
    volatile LONG64 CachedResults;

    //
    // Notification counts
    //
    volatile LONG64 ProcessNotifications;
    volatile LONG64 ThreadNotifications;
    volatile LONG64 ImageNotifications;
    volatile LONG64 RegistryNotifications;

    //
    // Performance metrics
    //
    volatile LONG64 TotalLatencyMs;
    volatile LONG64 MinLatencyMs;
    volatile LONG64 MaxLatencyMs;

    //
    // Error tracking
    //
    volatile LONG64 ConnectionErrors;
    volatile LONG64 MessageErrors;
    volatile LONG64 RetryCount;
    volatile LONG CircuitBreakerTrips;

    //
    // Memory statistics
    //
    volatile LONG64 BuffersAllocated;
    volatile LONG64 BuffersFreed;
    volatile LONG CurrentBuffersInUse;
    volatile LONG PeakBuffersInUse;

    //
    // Timing
    //
    LARGE_INTEGER StartTime;

} SB_STATISTICS, *PSB_STATISTICS;

//
// SHADOWSTRIKE_PROCESS_VERDICT_REPLY is defined in SharedDefs.h
// (included via MessageProtocol.h).
//

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize the scan bridge subsystem.
 *
 * Must be called during driver initialization before any scan operations.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeScanBridgeInitialize(
    VOID
);

/**
 * @brief Shutdown the scan bridge subsystem.
 *
 * Waits for pending operations and releases all resources.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeScanBridgeShutdown(
    VOID
);

// ============================================================================
// FILE SCAN OPERATIONS
// ============================================================================

/**
 * @brief Build a file scan request from callback data.
 *
 * Constructs a complete scan request message from filter callback data.
 * Captures file path, process context, and access information.
 *
 * @param Data          Filter callback data
 * @param FltObjects    Filter related objects
 * @param AccessType    Type of file access
 * @param Request       Receives pointer to allocated request
 * @param RequestSize   Receives size of the request
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 *
 * @note Caller must free Request with ShadowStrikeFreeMessageBuffer
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
);

/**
 * @brief Build file scan request with extended options.
 *
 * @param Data          Filter callback data
 * @param FltObjects    Filter related objects
 * @param AccessType    Type of file access
 * @param Options       Extended scan options
 * @param Request       Receives pointer to allocated request
 * @param RequestSize   Receives size of the request
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeBuildFileScanRequestEx(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _In_opt_ PSB_SCAN_OPTIONS Options,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
);

/**
 * @brief Send a scan request and wait for verdict.
 *
 * Sends the scan request to user-mode scanner and blocks until
 * a verdict is received or timeout expires.
 *
 * @param Request       Pointer to the scan request
 * @param RequestSize   Size of the request
 * @param Reply         Receives the verdict reply
 * @param ReplySize     On input, size of reply buffer. On output, actual size
 * @param TimeoutMs     Maximum wait time in milliseconds
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_TIMEOUT if timeout expires
 * @return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED if not connected
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeSendScanRequest(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_ PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
);

/**
 * @brief Send scan request with extended options and result.
 *
 * @param Request       Pointer to the scan request
 * @param RequestSize   Size of the request
 * @param Options       Extended scan options
 * @param Result        Receives extended scan result
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeSendScanRequestEx(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _In_opt_ PSB_SCAN_OPTIONS Options,
    _Out_ PSB_SCAN_RESULT Result
);

// ============================================================================
// NOTIFICATION OPERATIONS
// ============================================================================

/**
 * @brief Send process creation/termination notification.
 *
 * Fire-and-forget notification for process events.
 *
 * @param ProcessId     Target process ID
 * @param ParentId      Parent process ID
 * @param Create        TRUE for creation, FALSE for termination
 * @param ImageName     Process image path
 * @param CommandLine   Process command line (optional)
 *
 * @return STATUS_SUCCESS if queued successfully
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ BOOLEAN Create,
    _In_opt_ PUNICODE_STRING ImageName,
    _In_opt_ PUNICODE_STRING CommandLine
);

/**
 * @brief Send thread creation notification.
 *
 * Fire-and-forget notification for thread events.
 *
 * @param ProcessId     Target process ID
 * @param ThreadId      New thread ID
 * @param Create        TRUE for creation, FALSE for termination
 * @param IsRemote      TRUE if remote thread injection
 *
 * @return STATUS_SUCCESS if queued successfully
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendThreadNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create,
    _In_ BOOLEAN IsRemote
);

/**
 * @brief Send image load notification.
 *
 * Fire-and-forget notification for DLL/driver loads.
 *
 * @param ProcessId         Target process ID
 * @param FullImageName     Full path to loaded image (optional)
 * @param ImageInfo         Image information structure
 *
 * @return STATUS_SUCCESS if queued successfully
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendImageNotification(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
);

/**
 * @brief Send registry operation notification.
 *
 * Fire-and-forget notification for registry events.
 *
 * @param ProcessId     Process performing the operation
 * @param ThreadId      Thread performing the operation
 * @param Operation     Registry operation type
 * @param KeyPath       Registry key path
 * @param ValueName     Value name (optional)
 * @param Data          Value data (optional)
 * @param DataSize      Size of data
 * @param DataType      Registry data type
 *
 * @return STATUS_SUCCESS if queued successfully
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendRegistryNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ UINT8 Operation,
    _In_opt_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
);

// ============================================================================
// GENERIC MESSAGE OPERATIONS
// ============================================================================

/**
 * @brief Send a message to user-mode with optional reply.
 *
 * Low-level message sending function used by higher-level APIs.
 *
 * @param InputBuffer       Message to send
 * @param InputBufferSize   Size of message
 * @param OutputBuffer      Reply buffer (optional)
 * @param OutputBufferSize  On input, size of output buffer. On output, actual size
 * @param Timeout           Wait timeout (NULL = default)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendMessage(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_opt_ PLARGE_INTEGER Timeout
);

/**
 * @brief Send message with priority and retry options.
 *
 * @param InputBuffer       Message to send
 * @param InputBufferSize   Size of message
 * @param OutputBuffer      Reply buffer (optional)
 * @param OutputBufferSize  On input/output, size of output buffer
 * @param Priority          Message priority
 * @param MaxRetries        Maximum retry count
 * @param TimeoutMs         Timeout in milliseconds
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendMessageEx(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_ SB_MESSAGE_PRIORITY Priority,
    _In_ ULONG MaxRetries,
    _In_ ULONG TimeoutMs
);

// ============================================================================
// BUFFER MANAGEMENT
// ============================================================================

/**
 * @brief Allocate a message buffer.
 *
 * Allocates from lookaside list for standard sizes,
 * falls back to pool for larger allocations.
 * Buffer source is tracked for proper deallocation.
 *
 * @param Size  Minimum size required
 *
 * @return Pointer to allocated buffer, or NULL on failure
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Ret_maybenull_
PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ ULONG Size
);

/**
 * @brief Free a message buffer.
 *
 * Returns buffer to lookaside list or frees to pool based on
 * tracked allocation source.
 *
 * @param Buffer    Buffer to free (NULL is safe)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeFreeMessageBuffer(
    _In_opt_ PVOID Buffer
);

// ============================================================================
// MESSAGE CONSTRUCTION HELPERS
// ============================================================================

/**
 * @brief Initialize a message header with common fields.
 *
 * @param Header        Header to initialize
 * @param MessageType   Type of message
 * @param DataSize      Size of payload data (excluding header)
 *
 * @return STATUS_SUCCESS on success, STATUS_INVALID_PARAMETER if Header is NULL
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeInitMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header,
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ ULONG DataSize
);

/**
 * @brief Generate a unique message ID.
 *
 * Thread-safe message ID generation using interlocked operations.
 *
 * @return Unique 64-bit message ID
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
ShadowStrikeGenerateMessageId(
    VOID
);

// ============================================================================
// CONNECTION STATE
// ============================================================================

/**
 * @brief Check if user-mode scanner is connected.
 *
 * @return TRUE if at least one scanner is connected
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsUserModeConnected(
    VOID
);

/**
 * @brief Check if scan bridge is ready for operations.
 *
 * @return TRUE if initialized and connected
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeScanBridgeIsReady(
    VOID
);

/**
 * @brief Get circuit breaker state.
 *
 * @return Current circuit breaker state
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
SB_CIRCUIT_STATE
ShadowStrikeGetCircuitState(
    VOID
);

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get scan bridge statistics.
 *
 * @param Stats     Receives statistics snapshot
 *
 * @return STATUS_SUCCESS on success, STATUS_INVALID_PARAMETER if Stats is NULL
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetScanBridgeStatistics(
    _Out_ PSB_STATISTICS Stats
);

/**
 * @brief Reset scan bridge statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetScanBridgeStatistics(
    VOID
);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get verdict name string.
 *
 * @param Verdict   Scan verdict value
 *
 * @return Static string name of verdict
 *
 * @irql Any
 */
PCWSTR
ShadowStrikeGetVerdictName(
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
);

/**
 * @brief Get access type name string.
 *
 * @param AccessType    Access type value
 *
 * @return Static string name of access type
 *
 * @irql Any
 */
PCWSTR
ShadowStrikeGetAccessTypeName(
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType
);

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_SCAN_BRIDGE_H_
