/**
 * ============================================================================
 * ShadowStrike NGAV - ALPC PORT MONITOR (Enterprise Edition)
 * ============================================================================
 *
 * @file AlpcPortMonitor.h
 * @brief Enterprise-grade ALPC port monitoring for Windows kernel security.
 *
 * This module provides real ALPC (Advanced Local Procedure Call) monitoring:
 * - ALPC port creation/connection tracking
 * - Cross-session ALPC detection
 * - Impersonation abuse detection
 * - Handle passing via ALPC monitoring
 * - Sandbox escape attempt detection
 * - RPC/COM exploitation detection
 *
 * Architecture:
 * =============
 * 1. Object Callbacks (ObRegisterCallbacks) for ALPC Port object type
 *    -> Monitor handle creation/duplication to ALPC ports
 *    -> Detect suspicious access patterns
 *
 * 2. ETW Consumer (EVENT_TRACE_FLAG_ALPC)
 *    -> Real-time ALPC message flow monitoring
 *    -> Connection/disconnection events
 *    -> Message attribute tracking
 *
 * 3. Port Tracking Cache
 *    -> Hash table with chaining (no collision issues)
 *    -> Per-bucket locking for scalability
 *    -> LRU eviction for bounded memory
 *
 * Security Guarantees:
 * ====================
 * - BSOD-safe: Proper IRQL handling, reference counting, safe shutdown
 * - Thread-safe: Fine-grained locking with documented hierarchy
 * - Memory-safe: Lookaside lists, bounded allocations
 * - DoS-resistant: Rate limiting, queue depth limits
 * - Rundown protection: Safe shutdown with in-flight operation draining
 *
 * Lock Hierarchy (MUST follow this order):
 * ========================================
 * 1. HashBucket[n].Lock (EX_PUSH_LOCK) - Per-bucket, PASSIVE/APC only
 * 2. PortListLock (EX_PUSH_LOCK) - Global port list, PASSIVE/APC only
 * 3. PortEntry->ConnectionLock (EX_PUSH_LOCK) - Per-port, PASSIVE/APC only
 * 4. EventLock (KSPIN_LOCK) - Event queue, raises to DISPATCH
 *
 * CRITICAL FIXES IN VERSION 2.0.0:
 * ================================
 * - Fixed integrity level detection (now uses ProcessUtils properly)
 * - Added rundown protection for safe shutdown
 * - Fixed lock hierarchy violations
 * - Added KeFlushQueuedDpcs for DPC synchronization
 * - Fixed LRU eviction race conditions
 * - Added work item queue for PASSIVE_LEVEL operations from callbacks
 * - Removed deprecated ExAllocatePoolWithTag usage
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1134.001: Access Token Manipulation - Token Impersonation/Theft
 * - T1055.012: Process Injection - Process Hollowing
 * - T1559.001: Inter-Process Communication - Component Object Model
 * - T1559.002: Inter-Process Communication - Dynamic Data Exchange
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_ALPC_PORT_MONITOR_H
#define SHADOWSTRIKE_ALPC_PORT_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "AlpcTypes.h"

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global ALPC monitor state.
 *
 * Defined in AlpcPortMonitor.c.
 */
extern SHADOW_ALPC_MONITOR_STATE g_AlpcPortMonitorState;

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize ALPC port monitoring subsystem.
 *
 * Registers object callbacks for ALPC Port type, initializes tracking
 * infrastructure, and starts worker thread.
 *
 * Must be called during driver initialization at PASSIVE_LEVEL.
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *         STATUS_UNSUCCESSFUL if callback registration fails
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowAlpcInitialize(
    VOID
    );

/**
 * @brief Cleanup ALPC port monitoring subsystem.
 *
 * Unregisters callbacks, waits for in-flight operations to complete,
 * frees all tracked entries. BSOD-safe - handles partial initialization.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowAlpcCleanup(
    VOID
    );

/**
 * @brief Check if ALPC monitoring is initialized and active.
 *
 * @return TRUE if monitoring is active, FALSE otherwise
 *
 * @irql Any
 */
BOOLEAN
ShadowAlpcIsActive(
    VOID
    );

// ============================================================================
// PORT TRACKING
// ============================================================================

/**
 * @brief Track an ALPC port object.
 *
 * Creates or updates tracking entry for an ALPC port.
 *
 * @param PortObject    ALPC port kernel object
 * @param OwnerPid      Process ID of port owner
 * @param PortType      Type of port (server/client/connection)
 * @param PortName      Optional port name (can be NULL)
 * @param Entry         [out] Receives port entry (caller must release)
 *
 * @return STATUS_SUCCESS on success
 *
 * @note Caller must call ShadowAlpcReleasePortEntry when done
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowAlpcTrackPort(
    _In_ PVOID PortObject,
    _In_ HANDLE OwnerPid,
    _In_ SHADOW_ALPC_PORT_TYPE PortType,
    _In_opt_ PCUNICODE_STRING PortName,
    _Outptr_ PSHADOW_ALPC_PORT_ENTRY* Entry
    );

/**
 * @brief Find existing port tracking entry.
 *
 * @param PortObject    ALPC port kernel object
 * @param Entry         [out] Receives port entry if found (caller must release)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowAlpcFindPort(
    _In_ PVOID PortObject,
    _Outptr_ PSHADOW_ALPC_PORT_ENTRY* Entry
    );

/**
 * @brief Release port entry reference.
 *
 * Decrements reference count. When count reaches zero, entry is freed.
 *
 * @param Entry     Port entry to release (can be NULL)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowAlpcReleasePortEntry(
    _In_opt_ PSHADOW_ALPC_PORT_ENTRY Entry
    );

/**
 * @brief Remove port tracking entry.
 *
 * Called when a port is closed.
 *
 * @param PortObject    ALPC port kernel object
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowAlpcRemovePort(
    _In_ PVOID PortObject
    );

// ============================================================================
// CONNECTION TRACKING
// ============================================================================

/**
 * @brief Track an ALPC connection.
 *
 * @param PortEntry         Server port entry
 * @param ClientPid         Client process ID
 * @param ClientPortObject  Client's port object
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowAlpcTrackConnection(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY PortEntry,
    _In_ HANDLE ClientPid,
    _In_ PVOID ClientPortObject
    );

/**
 * @brief Remove connection from port.
 *
 * @param PortEntry         Server port entry
 * @param ClientPortObject  Client's port object
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowAlpcRemoveConnection(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY PortEntry,
    _In_ PVOID ClientPortObject
    );

// ============================================================================
// THREAT ANALYSIS
// ============================================================================

/**
 * @brief Analyze ALPC operation for threats.
 *
 * Examines operation context and calculates threat score.
 * This function is IRQL-safe and can be called from callbacks.
 *
 * @param Context       Operation context (in/out, receives analysis results)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowAlpcAnalyzeOperation(
    _Inout_ PSHADOW_ALPC_OPERATION_CONTEXT Context
    );

/**
 * @brief Determine verdict for ALPC operation.
 *
 * @param Context       Analyzed operation context
 *
 * @return Verdict (allow, monitor, strip, block)
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
SHADOW_ALPC_VERDICT
ShadowAlpcDetermineVerdict(
    _In_ PSHADOW_ALPC_OPERATION_CONTEXT Context
    );

/**
 * @brief Check if port name is sensitive.
 *
 * Matches against known sensitive ALPC port patterns.
 *
 * @param PortName      Port name to check
 * @param ThreatWeight  [out] Receives threat weight if sensitive
 *
 * @return TRUE if sensitive, FALSE otherwise
 *
 * @irql Any
 */
BOOLEAN
ShadowAlpcIsSensitivePort(
    _In_ PCWSTR PortName,
    _Out_opt_ PULONG ThreatWeight
    );

/**
 * @brief Check rate limit for port.
 *
 * @param PortEntry     Port entry to check
 *
 * @return TRUE if rate limit exceeded, FALSE otherwise
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowAlpcCheckRateLimit(
    _Inout_ PSHADOW_ALPC_PORT_ENTRY PortEntry
    );

// ============================================================================
// EVENT QUEUE
// ============================================================================

/**
 * @brief Queue ALPC security event for user-mode notification.
 *
 * @param EventType     Type of event
 * @param Context       Operation context
 * @param WasBlocked    Whether operation was blocked
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowAlpcQueueEvent(
    _In_ SHADOW_ALPC_EVENT_TYPE EventType,
    _In_ PSHADOW_ALPC_OPERATION_CONTEXT Context,
    _In_ BOOLEAN WasBlocked
    );

/**
 * @brief Dequeue ALPC event for delivery.
 *
 * @param Event     [out] Receives event (caller must free)
 *
 * @return STATUS_SUCCESS if event dequeued, STATUS_NO_MORE_ENTRIES if empty
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowAlpcDequeueEvent(
    _Outptr_ PSHADOW_ALPC_EVENT* Event
    );

/**
 * @brief Free an ALPC event.
 *
 * @param Event     Event to free
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowAlpcFreeEvent(
    _In_ PSHADOW_ALPC_EVENT Event
    );

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get ALPC monitoring statistics.
 *
 * @param Stats     [out] Receives statistics snapshot
 *
 * @irql Any
 */
VOID
ShadowAlpcGetStatistics(
    _Out_ PSHADOW_ALPC_STATISTICS Stats
    );

/**
 * @brief Reset ALPC monitoring statistics.
 *
 * @irql Any
 */
VOID
ShadowAlpcResetStatistics(
    VOID
    );

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief Enable or disable ALPC monitoring.
 *
 * @param Enable    TRUE to enable, FALSE to disable
 *
 * @irql Any
 */
VOID
ShadowAlpcSetMonitoringEnabled(
    _In_ BOOLEAN Enable
    );

/**
 * @brief Enable or disable ALPC blocking.
 *
 * @param Enable    TRUE to enable blocking, FALSE for monitor-only
 *
 * @irql Any
 */
VOID
ShadowAlpcSetBlockingEnabled(
    _In_ BOOLEAN Enable
    );

/**
 * @brief Set threat score threshold for blocking/alerting.
 *
 * @param Threshold     Threat score threshold (0-100)
 *
 * @irql Any
 */
VOID
ShadowAlpcSetThreatThreshold(
    _In_ ULONG Threshold
    );

// ============================================================================
// INTERNAL CALLBACKS (Private, but declared for clarity)
// ============================================================================

/**
 * @brief Pre-operation callback for ALPC port access.
 *
 * Called before ALPC port handle is opened or duplicated.
 * This callback is IRQL-safe and uses deferred work items for
 * operations requiring PASSIVE_LEVEL.
 *
 * @irql <= APC_LEVEL
 */
OB_PREOP_CALLBACK_STATUS
ShadowAlpcPortPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Post-operation callback for ALPC port access.
 *
 * Called after ALPC port handle operation completes.
 *
 * @irql <= APC_LEVEL
 */
VOID
ShadowAlpcPortPostCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_ALPC_PORT_MONITOR_H
