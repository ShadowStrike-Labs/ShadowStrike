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

#include <fltKernel.h>
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

    /// @brief Lookaside list for file context allocations
    NPAGED_LOOKASIDE_LIST FileContextLookaside;

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

/// @brief Increment total operations counter (for statistics only)
#define SHADOWSTRIKE_COUNT_OPERATION() \
    InterlockedIncrement64(&g_DriverData.TotalOperationsProcessed)

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
