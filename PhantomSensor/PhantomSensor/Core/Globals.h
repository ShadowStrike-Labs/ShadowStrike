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
 * ShadowStrike NGAV - DRIVER GLOBALS
 * ============================================================================
 *
 * @file Globals.h
 * @brief Global driver state and configuration.
 *
 * Contains all global variables, configuration structures, and state
 * management for the ShadowStrike minifilter driver.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_GLOBALS_H
#define SHADOWSTRIKE_GLOBALS_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)
#include <ntddk.h>
#include <wdm.h>
#include "../../Shared/SharedDefs.h"
#include "../../Shared/MessageProtocol.h"
#include "../../Shared/VerdictTypes.h"
#include "../../Shared/ErrorCodes.h"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

typedef struct _SHADOWSTRIKE_DRIVER_DATA    SHADOWSTRIKE_DRIVER_DATA;
typedef struct _SHADOWSTRIKE_CONFIG         SHADOWSTRIKE_CONFIG;
typedef struct _SHADOWSTRIKE_STATISTICS     SHADOWSTRIKE_STATISTICS;
typedef struct _SHADOWSTRIKE_CLIENT_PORT    SHADOWSTRIKE_CLIENT_PORT;

// ============================================================================
// DRIVER CONFIGURATION
// ============================================================================

/**
 * @brief Driver configuration settings.
 *
 * These settings control the behavior of the minifilter and can be
 * updated at runtime via the control port.
 */
typedef struct _SHADOWSTRIKE_CONFIG {

    /// @brief Enable file system filtering
    BOOLEAN FilteringEnabled;

    /// @brief Enable scan on file open
    BOOLEAN ScanOnOpen;

    /// @brief Enable scan on execute/map
    BOOLEAN ScanOnExecute;

    /// @brief Enable scan on write completion
    BOOLEAN ScanOnWrite;

    /// @brief Enable asynchronous notifications
    BOOLEAN NotificationsEnabled;

    /// @brief Block on scan timeout (FALSE = allow)
    BOOLEAN BlockOnTimeout;

    /// @brief Block on scan error (FALSE = allow)
    BOOLEAN BlockOnError;

    /// @brief Scan network files
    BOOLEAN ScanNetworkFiles;

    /// @brief Scan removable media
    BOOLEAN ScanRemovableMedia;

    /// @brief Enable self-protection
    BOOLEAN SelfProtectionEnabled;

    /// @brief Enable process monitoring
    BOOLEAN ProcessMonitorEnabled;

    /// @brief Enable registry monitoring
    BOOLEAN RegistryMonitorEnabled;

    /// @brief Enable kernel-side caching
    BOOLEAN CacheEnabled;

    /// @brief Padding for alignment
    BOOLEAN Reserved[2];

    /// @brief Maximum file size to scan (0 = unlimited)
    ULONG64 MaxScanFileSize;

    /// @brief Scan timeout in milliseconds
    ULONG ScanTimeoutMs;

    /// @brief Cache TTL in seconds
    ULONG CacheTTLSeconds;

    /// @brief Maximum pending requests before rejecting
    ULONG MaxPendingRequests;

} SHADOWSTRIKE_CONFIG, *PSHADOWSTRIKE_CONFIG;

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Driver statistics counters.
 *
 * All counters are updated atomically using InterlockedIncrement/Add.
 */
typedef struct _SHADOWSTRIKE_STATISTICS {

    /// @brief Total IRP_MJ_CREATE operations seen
    volatile LONG64 TotalCreateOperations;

    /// @brief Total files scanned
    volatile LONG64 TotalFilesScanned;

    /// @brief Files allowed after scan
    volatile LONG64 FilesAllowed;

    /// @brief Files blocked
    volatile LONG64 FilesBlocked;

    /// @brief Files quarantined
    volatile LONG64 FilesQuarantined;

    /// @brief Scan timeouts
    volatile LONG64 ScanTimeouts;

    /// @brief Scan errors
    volatile LONG64 ScanErrors;

    /// @brief Cache hits
    volatile LONG64 CacheHits;

    /// @brief Cache misses
    volatile LONG64 CacheMisses;

    /// @brief Exclusion matches (skipped scans)
    volatile LONG64 ExclusionMatches;

    /// @brief Total process creations seen
    volatile LONG64 TotalProcessCreations;

    /// @brief Processes blocked
    volatile LONG64 ProcessesBlocked;

    /// @brief Total registry operations seen
    volatile LONG64 TotalRegistryOperations;

    /// @brief Registry operations blocked
    volatile LONG64 RegistryOperationsBlocked;

    /// @brief Self-protection blocks (tamper attempts)
    volatile LONG64 SelfProtectionBlocks;

    /// @brief Current pending scan requests
    volatile LONG PendingRequests;

    /// @brief Peak pending requests
    volatile LONG PeakPendingRequests;

    /// @brief Total messages sent to user-mode
    volatile LONG64 MessagesSent;

    /// @brief Total replies received from user-mode
    volatile LONG64 RepliesReceived;

    /// @brief Messages dropped (queue full)
    volatile LONG64 MessagesDropped;

    /// @brief Driver start time
    LARGE_INTEGER StartTime;

} SHADOWSTRIKE_STATISTICS, *PSHADOWSTRIKE_STATISTICS;

// ============================================================================
// CLIENT PORT CONTEXT
// ============================================================================

/**
 * @brief Per-client connection context.
 */
typedef struct _SHADOWSTRIKE_CLIENT_PORT {

    /// @brief Client port handle
    PFLT_PORT ClientPort;

    /// @brief Client process ID
    HANDLE ClientProcessId;

    /// @brief Connection time
    LARGE_INTEGER ConnectedTime;

    /// @brief Messages sent to this client
    volatile LONG64 MessagesSent;

    /// @brief Replies received from this client
    volatile LONG64 RepliesReceived;

    /// @brief Is this the primary scanner connection
    BOOLEAN IsPrimaryScanner;

    /// @brief Reserved
    BOOLEAN Reserved[7];

} SHADOWSTRIKE_CLIENT_PORT, *PSHADOWSTRIKE_CLIENT_PORT;

// ============================================================================
// MAIN DRIVER DATA STRUCTURE
// ============================================================================

/**
 * @brief Global driver data structure.
 *
 * This structure holds all global state for the driver. Only one instance
 * exists (g_DriverData) and it is initialized in DriverEntry.
 */
typedef struct _SHADOWSTRIKE_DRIVER_DATA {

    // =========================================================================
    // Filter Manager
    // =========================================================================

    /// @brief Filter handle from FltRegisterFilter
    PFLT_FILTER FilterHandle;

    /// @brief Server communication port handle
    PFLT_PORT ServerPort;

    /// @brief Connected client ports (up to SHADOWSTRIKE_MAX_CONNECTIONS)
    SHADOWSTRIKE_CLIENT_PORT ClientPorts[SHADOWSTRIKE_MAX_CONNECTIONS];

    /// @brief Current connected client count
    volatile LONG ConnectedClients;

    /// @brief Lock for client port array
    EX_PUSH_LOCK ClientPortLock;

    // =========================================================================
    // Callback Registrations
    // =========================================================================

    /// @brief Process notify callback registered
    BOOLEAN ProcessNotifyRegistered;

    /// @brief Thread notify callback registered
    BOOLEAN ThreadNotifyRegistered;

    /// @brief Image load callback registered
    BOOLEAN ImageNotifyRegistered;

    /// @brief Reserved
    BOOLEAN Reserved1;

    /// @brief Registry callback cookie
    LARGE_INTEGER RegistryCallbackCookie;

    /// @brief Object callback handle
    PVOID ObjectCallbackHandle;

    // =========================================================================
    // State
    // =========================================================================

    /// @brief Driver is initialized
    BOOLEAN Initialized;

    /// @brief Filtering is started (FltStartFiltering called)
    BOOLEAN FilteringStarted;

    /// @brief Driver is shutting down
    BOOLEAN ShuttingDown;

    /// @brief Reserved
    BOOLEAN Reserved2;

    /// @brief Driver unload event (signaled when safe to unload)
    KEVENT UnloadEvent;

    /// @brief Rundown protection for safe callback unload synchronization
    /// This REPLACES the old OutstandingOperations counter with proper kernel primitive
    EX_RUNDOWN_REF RundownProtection;

    /// @brief Per-callback in-flight counters (diagnostic only - NOT for synchronization).
    /// Read on bounded-wait timeout to identify the stuck callback class so the
    /// driver can emit actionable telemetry instead of a silent watchdog reboot.
    volatile LONG InFlightProcess;
    volatile LONG InFlightThread;
    volatile LONG InFlightPreAcquireSection;

    /// @brief Legacy counter for statistics only (NOT for synchronization)
    volatile LONG64 TotalOperationsProcessed;

    // =========================================================================
    // Configuration
    // =========================================================================

    /// @brief Current configuration
    SHADOWSTRIKE_CONFIG Config;

    /// @brief Configuration lock
    EX_PUSH_LOCK ConfigLock;

    // =========================================================================
    // Statistics
    // =========================================================================

    /// @brief Driver statistics
    SHADOWSTRIKE_STATISTICS Stats;

    // =========================================================================
    // Memory
    // =========================================================================

    /// @brief Lookaside list for message allocations
    NPAGED_LOOKASIDE_LIST MessageLookaside;

    /// @brief Lookaside list for stream context allocations
    NPAGED_LOOKASIDE_LIST StreamContextLookaside;

    /// @brief Lookaside lists initialized
    BOOLEAN LookasideInitialized;

    /// @brief Reserved
    BOOLEAN Reserved3[7];

    // =========================================================================
    // Message ID Generation
    // =========================================================================

    /// @brief Next message ID (atomically incremented)
    volatile LONG64 NextMessageId;

    // =========================================================================
    // Protected Processes
    // =========================================================================

    /// @brief Protected process list (for self-protection)
    LIST_ENTRY ProtectedProcessList;

    /// @brief Protected process list lock
    EX_PUSH_LOCK ProtectedProcessLock;

    /// @brief Count of protected processes
    volatile LONG ProtectedProcessCount;

    // =========================================================================
    // Driver Object
    // =========================================================================

    /// @brief Driver object pointer
    PDRIVER_OBJECT DriverObject;

    // =========================================================================
    // Boot Phase Tracking (added v1.0.13.0 — winlogon grey-screen fix)
    // =========================================================================
    //
    // FullyOperational is the AUTHORITATIVE flag indicating that DriverEntry
    // has run to completion AND FltStartFiltering returned success AND the
    // user-mode communication port is created. All callbacks must consult
    // ShadowStrikeIsFullyOperational() — and additionally ShadowStrikeInBootGrace()
    // for expensive boot-phase-only paths — before performing any work that
    // could block winlogon/csrss/smss filesystem IO at boot.
    //
    // The legacy Initialized/FilteringStarted booleans REMAIN VALID and are
    // still set in lockstep — FullyOperational is set strictly after both,
    // so it is a superset gate and is safe to use alongside SHADOWSTRIKE_IS_READY().
    //

    /// @brief Driver is fully operational (atomic). 0 = not ready, 1 = ready.
    /// Set strictly AFTER FltStartFiltering returns success AND CommPort exists.
    /// Pre-callbacks in foreign agents MUST consult this via ShadowStrikeIsFullyOperational().
    volatile LONG FullyOperational;

    /// @brief Performance-counter tick captured at the start of DriverEntry.
    /// Other modules compute "elapsed since DriverEntry" by subtracting from
    /// KeQueryPerformanceCounter(NULL).QuadPart.
    LARGE_INTEGER BootPhaseStartTick;

    /// @brief Performance-counter tick at which the 90-second boot-grace window expires.
    /// While KeQueryPerformanceCounter() < BootGraceUntilTick, modules should
    /// skip expensive scanning to avoid stalling winlogon/csrss/smss IO.
    LARGE_INTEGER BootGraceUntilTick;

    /// @brief Cached performance counter frequency (Hz). Populated during DriverEntry.
    LARGE_INTEGER PerfFrequency;

    // -------------------------------------------------------------------------
    // Deferred post-init work queue
    // -------------------------------------------------------------------------
    //
    // Subsystems may queue work items here during their init phase that MUST
    // NOT execute until FltStartFiltering has returned and the driver is
    // marked FullyOperational. DriverEntry drains the list at the very end
    // of the boot sequence by invoking each callback at PASSIVE_LEVEL.
    //
    // After PostInitDrained transitions to 1, the queue is permanently closed
    // and further calls to ShadowStrikeQueuePostInitWork() will execute the
    // callback inline (the driver is already operational).
    //

    /// @brief Spinlock guarding PostInitWorkList.
    KSPIN_LOCK PostInitWorkLock;

    /// @brief Head of deferred post-init work items.
    LIST_ENTRY PostInitWorkList;

    /// @brief 0 = queueing allowed, 1 = drain complete (queue closed).
    volatile LONG PostInitDrained;

} SHADOWSTRIKE_DRIVER_DATA, *PSHADOWSTRIKE_DRIVER_DATA;

// ============================================================================
// GLOBAL VARIABLE DECLARATION
// ============================================================================

/**
 * @brief Global driver data instance.
 *
 * Defined in DriverEntry.c, accessible from all driver modules.
 */
extern SHADOWSTRIKE_DRIVER_DATA g_DriverData;

// ============================================================================
// HELPER MACROS
// ============================================================================

/// @brief Check if driver is ready to process requests (uses volatile read with acquire semantics)
#define SHADOWSTRIKE_IS_READY() \
    (ReadBooleanAcquire(&g_DriverData.Initialized) && \
     ReadBooleanAcquire(&g_DriverData.FilteringStarted) && \
     !ReadBooleanAcquire(&g_DriverData.ShuttingDown))

/// @brief Check if user-mode is connected
#define SHADOWSTRIKE_USER_MODE_CONNECTED() \
    (g_DriverData.ConnectedClients > 0)

/// @brief Acquire rundown protection before entering callback operation
/// Returns TRUE if acquired (safe to proceed), FALSE if driver is unloading
#define SHADOWSTRIKE_ACQUIRE_RUNDOWN() \
    ExAcquireRundownProtection(&g_DriverData.RundownProtection)

/// @brief Release rundown protection after callback operation completes
#define SHADOWSTRIKE_RELEASE_RUNDOWN() \
    ExReleaseRundownProtection(&g_DriverData.RundownProtection)

//
// Per-callback rundown acquire/release macros. These wrap the global rundown
// acquire with a per-callback InterlockedIncrement/Decrement on a diagnostic
// counter so the unload path can identify which callback class is stuck on
// the global rundown when the bounded wait times out.
//
// The counter is touched ONLY after a successful global acquire and BEFORE
// the matching release, which means the counter mirrors the contribution of
// that callback class to the global rundown refcount exactly.
//

/// @brief Per-callback rundown acquire - Process notify callback class.
#define SHADOWSTRIKE_ACQUIRE_RUNDOWN_PROCESS()                              \
    (ExAcquireRundownProtection(&g_DriverData.RundownProtection)            \
        ? (InterlockedIncrement(&g_DriverData.InFlightProcess), TRUE)       \
        : FALSE)

/// @brief Per-callback rundown release - Process notify callback class.
#define SHADOWSTRIKE_RELEASE_RUNDOWN_PROCESS()                              \
    do {                                                                    \
        InterlockedDecrement(&g_DriverData.InFlightProcess);                \
        ExReleaseRundownProtection(&g_DriverData.RundownProtection);        \
    } while (0)

/// @brief Per-callback rundown acquire - Thread notify callback class.
#define SHADOWSTRIKE_ACQUIRE_RUNDOWN_THREAD()                               \
    (ExAcquireRundownProtection(&g_DriverData.RundownProtection)            \
        ? (InterlockedIncrement(&g_DriverData.InFlightThread), TRUE)        \
        : FALSE)

/// @brief Per-callback rundown release - Thread notify callback class.
#define SHADOWSTRIKE_RELEASE_RUNDOWN_THREAD()                               \
    do {                                                                    \
        InterlockedDecrement(&g_DriverData.InFlightThread);                 \
        ExReleaseRundownProtection(&g_DriverData.RundownProtection);        \
    } while (0)

/// @brief Per-callback rundown acquire - PreAcquireSection callback class.
#define SHADOWSTRIKE_ACQUIRE_RUNDOWN_PAS()                                  \
    (ExAcquireRundownProtection(&g_DriverData.RundownProtection)            \
        ? (InterlockedIncrement(&g_DriverData.InFlightPreAcquireSection),   \
           TRUE)                                                            \
        : FALSE)

/// @brief Per-callback rundown release - PreAcquireSection callback class.
#define SHADOWSTRIKE_RELEASE_RUNDOWN_PAS()                                  \
    do {                                                                    \
        InterlockedDecrement(&g_DriverData.InFlightPreAcquireSection);      \
        ExReleaseRundownProtection(&g_DriverData.RundownProtection);        \
    } while (0)

/// @brief Increment total operations counter (for statistics only)
#define SHADOWSTRIKE_COUNT_OPERATION() \
    InterlockedIncrement64(&g_DriverData.TotalOperationsProcessed)

//
// NOTE: SHADOWSTRIKE_ENTER_OPERATION / SHADOWSTRIKE_LEAVE_OPERATION were
// removed. All callbacks use SHADOWSTRIKE_ACQUIRE_RUNDOWN /
// SHADOWSTRIKE_RELEASE_RUNDOWN directly. The previous referenced caller
// (ShadowStrikePreAcquireForSectionSync) has itself been removed and the
// IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION path now lives in
// PreAcquireSection.c.
//

/// @brief Generate next message ID
#define SHADOWSTRIKE_NEXT_MESSAGE_ID() \
    ((UINT64)InterlockedIncrement64(&g_DriverData.NextMessageId))

/// @brief Increment statistic counter
#define SHADOWSTRIKE_INC_STAT(field) \
    InterlockedIncrement64(&g_DriverData.Stats.field)

/// @brief Add to statistic counter
#define SHADOWSTRIKE_ADD_STAT(field, value) \
    InterlockedAdd64(&g_DriverData.Stats.field, (LONG64)(value))

// ============================================================================
// BOOT-PHASE OPERATIONAL GATES (v1.0.13.0)
// ============================================================================
//
// These helpers are the canonical guards that ALL callback modules must use
// before doing any non-trivial work. They are intentionally branch-prediction
// friendly (single atomic read / single subtraction) and safe to call at
// IRQL <= DISPATCH_LEVEL.
//
// Usage from foreign callback modules (Process/Thread/Image/Registry/Object/FS):
//
//     if (!ShadowStrikeIsFullyOperational()) {
//         return STATUS_SUCCESS;            // no-op until DriverEntry done
//     }
//     if (ShadowStrikeInBootGrace()) {
//         return STATUS_SUCCESS;            // skip heavy scan during first 90s
//     }
//

/**
 * @brief Returns TRUE iff DriverEntry has completed successfully and the
 *        driver is fully operational (FltStartFiltering returned success
 *        AND user-mode communication port has been created).
 *
 * @irql <= DISPATCH_LEVEL
 */
static __forceinline BOOLEAN
ShadowStrikeIsFullyOperational(VOID)
{
    return InterlockedCompareExchange(&g_DriverData.FullyOperational, 0, 0) != 0;
}

/**
 * @brief Returns TRUE while the 90-second boot-grace window is still active.
 *        Modules SHOULD short-circuit expensive scan paths while this is TRUE
 *        so that winlogon / csrss / smss filesystem IO is not stalled.
 *
 *        Reads the cached BootGraceUntilTick (set once during DriverEntry)
 *        and the live performance counter. Cheap; safe to call from hot paths.
 *
 * @irql <= DISPATCH_LEVEL
 */
static __forceinline BOOLEAN
ShadowStrikeInBootGrace(VOID)
{
    LARGE_INTEGER now;
    LONGLONG until = g_DriverData.BootGraceUntilTick.QuadPart;

    if (until == 0) {
        //
        // Grace window not yet initialized — treat as active so callers
        // skip heavy work until DriverEntry installs the deadline.
        //
        return TRUE;
    }

    now = KeQueryPerformanceCounter(NULL);
    return (BOOLEAN)(now.QuadPart < until);
}

// ============================================================================
// DEFERRED POST-INIT WORK QUEUE (v1.0.13.0)
// ============================================================================

/**
 * @brief Signature for deferred post-init work callbacks.
 *
 * Invoked at PASSIVE_LEVEL after FltStartFiltering has succeeded and the
 * driver has transitioned to FullyOperational. Must not block.
 */
typedef VOID (*PFN_SHADOWSTRIKE_POST_INIT)(_In_opt_ PVOID Context);

/**
 * @brief Queue a callback to be invoked after DriverEntry completes.
 *
 * If the driver is already fully operational at the time of the call, the
 * callback is invoked inline. Otherwise it is appended to the post-init
 * queue and run when ShadowStrikeDrainPostInitWork() is called from the
 * tail of DriverEntry.
 *
 * @param Callback  Required. Function to invoke.
 * @param Context   Optional. Passed through to Callback.
 * @return STATUS_SUCCESS on enqueue/inline success, STATUS_INSUFFICIENT_RESOURCES on alloc fail.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueuePostInitWork(
    _In_ PFN_SHADOWSTRIKE_POST_INIT Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Drain the post-init queue and mark it closed.
 *
 * Called once from DriverEntry, immediately before FullyOperational is set
 * to 1. After this call, ShadowStrikeQueuePostInitWork() invokes callbacks
 * inline rather than enqueueing.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeDrainPostInitWork(VOID);

// ============================================================================
// VOLATILE BOOLEAN ACCESS HELPERS
// ============================================================================
//
// ReadBooleanAcquire and WriteBooleanRelease are provided by wdm.h
// in WDK 10.0.26100+. No custom implementations needed.
//

// ============================================================================
// DEFAULT CONFIGURATION
// ============================================================================

/**
 * @brief Initialize configuration with defaults.
 */
FORCEINLINE
VOID
ShadowStrikeInitDefaultConfig(
    _Out_ PSHADOWSTRIKE_CONFIG Config
    )
{
    RtlZeroMemory(Config, sizeof(SHADOWSTRIKE_CONFIG));

    Config->FilteringEnabled        = TRUE;
    Config->ScanOnOpen              = TRUE;
    Config->ScanOnExecute           = TRUE;
    Config->ScanOnWrite             = FALSE;
    Config->NotificationsEnabled    = TRUE;
    Config->BlockOnTimeout          = FALSE;
    Config->BlockOnError            = FALSE;
    Config->ScanNetworkFiles        = TRUE;
    Config->ScanRemovableMedia      = TRUE;
    Config->SelfProtectionEnabled   = TRUE;
    Config->ProcessMonitorEnabled   = TRUE;
    Config->RegistryMonitorEnabled  = TRUE;
    Config->CacheEnabled            = TRUE;
    Config->MaxScanFileSize         = 0;        // Unlimited
    Config->ScanTimeoutMs           = 30000;    // 30 seconds
    Config->CacheTTLSeconds         = 300;      // 5 minutes
    Config->MaxPendingRequests      = 10000;
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_GLOBALS_H
