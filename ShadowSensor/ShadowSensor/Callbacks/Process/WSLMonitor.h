/*++
===============================================================================
ShadowStrike NGAV - WSL/CONTAINER MONITORING MODULE
===============================================================================

@file WSLMonitor.h
@brief Windows Subsystem for Linux and container escape detection.

Monitors WSL2 process activity and detects container-to-host escape attempts:
  - WSL process chain identification (wsl.exe → wslhost.exe → Pico processes)
  - Pico process subsystem detection (LxssManager)
  - WSL-to-Windows filesystem access monitoring (/mnt/c/ → C:\ mapping)
  - Container escape pattern detection
  - Cross-subsystem process creation tracking

Integration Points:
  - ProcessNotify callback → WslMonCheckProcessCreate()
  - ImageNotify callback → WslMonCheckImageLoad()
  - PreCreate callback → WslMonCheckFileAccess()
  - DriverEntry → WslMonInitialize() / WslMonShutdown()

MITRE ATT&CK Coverage:
  - T1610: Deploy Container
  - T1611: Escape to Host
  - T1059.004: Unix Shell (WSL bash execution)
  - T1106: Native API (Pico process API abuse)

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define WSL_POOL_TAG            'lSWF'  // FWSl - WSL Monitor
#define WSL_PROCESS_POOL_TAG    'pSWF'  // FWSp - Process Entry
#define WSL_EVENT_POOL_TAG      'eSWF'  // FWSe - Event

// ============================================================================
// CONFIGURATION
// ============================================================================

#define WSL_MAX_TRACKED_PROCESSES       512
#define WSL_MAX_ESCAPE_PATTERNS         32
#define WSL_PROCESS_NAME_MAX            260

// ============================================================================
// WSL PROCESS CLASSIFICATION
// ============================================================================

typedef enum _WSL_PROCESS_TYPE {
    WslProcess_None = 0,            // Not WSL-related
    WslProcess_Launcher,            // wsl.exe launcher
    WslProcess_Host,                // wslhost.exe (WSL2 VM host)
    WslProcess_Init,                // init (WSL2 PID 1 inside VM)
    WslProcess_Service,             // wslservice.exe
    WslProcess_Pico,                // Pico process (WSL1 direct)
    WslProcess_Child                // Child of WSL process chain
} WSL_PROCESS_TYPE;

// ============================================================================
// ESCAPE ATTEMPT TYPE
// ============================================================================

typedef enum _WSL_ESCAPE_TYPE {
    WslEscape_None = 0,
    WslEscape_FileSystemAccess,     // WSL process accessing Windows FS directly
    WslEscape_ProcessCreation,      // WSL spawning native Windows process
    WslEscape_RegistryAccess,       // WSL process accessing Windows registry
    WslEscape_NetworkPivot,         // WSL network used to pivot to host
    WslEscape_DriverLoad,           // Attempting driver load from WSL context
    WslEscape_PicoEscape,           // Pico subsystem boundary violation
    WslEscape_CredentialAccess      // WSL accessing credential files
} WSL_ESCAPE_TYPE;

// ============================================================================
// TRACKED WSL PROCESS
// ============================================================================

typedef struct _WSL_TRACKED_PROCESS {

    LIST_ENTRY Link;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    WSL_PROCESS_TYPE ProcessType;

    //
    // Process image name
    //
    WCHAR ImageName[WSL_PROCESS_NAME_MAX];
    USHORT ImageNameLength;

    //
    // Tracking
    //
    LARGE_INTEGER CreateTime;
    volatile LONG FileAccessCount;
    volatile LONG EscapeAttempts;
    volatile LONG SuspiciousActions;

    //
    // Subsystem info
    //
    BOOLEAN IsPicoProcess;
    ULONG SubsystemId;

} WSL_TRACKED_PROCESS, *PWSL_TRACKED_PROCESS;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _WSL_STATISTICS {

    volatile LONG64 WslProcessesDetected;
    volatile LONG64 PicoProcessesDetected;
    volatile LONG64 FileSystemCrossings;
    volatile LONG64 EscapeAttemptsDetected;
    volatile LONG64 SuspiciousSpawns;
    volatile LONG64 CredentialAccessAttempts;

} WSL_STATISTICS, *PWSL_STATISTICS;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WslMonInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WslMonShutdown(VOID);

// ============================================================================
// PUBLIC API — DETECTION (called from existing callbacks)
// ============================================================================

/**
 * @brief Check if a new process is WSL-related and track it.
 *
 * Called from ProcessNotify callback for create events.
 *
 * @param[in] ProcessId         New process ID.
 * @param[in] ParentProcessId   Parent process ID.
 * @param[in] ImageFileName     Process image file name (can be NULL).
 *
 * @return WSL_PROCESS_TYPE classification.
 */
_IRQL_requires_(PASSIVE_LEVEL)
WSL_PROCESS_TYPE
WslMonCheckProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName
    );

/**
 * @brief Handle process termination and clean up tracking.
 *
 * @param[in] ProcessId     Terminating process ID.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WslMonProcessTerminated(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Check if a file access from a WSL process crosses into Windows FS.
 *
 * Called from PreCreate callback when source is WSL-classified process.
 *
 * @param[in] ProcessId     Requesting process ID.
 * @param[in] FileName      Target file path.
 *
 * @return WSL_ESCAPE_TYPE if suspicious crossing detected, WslEscape_None otherwise.
 */
_IRQL_requires_max_(APC_LEVEL)
WSL_ESCAPE_TYPE
WslMonCheckFileAccess(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    );

/**
 * @brief Check if a process is tracked as WSL-related.
 *
 * @param[in] ProcessId     Process to query.
 *
 * @return TRUE if process is in WSL tracking table.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WslMonIsWslProcess(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Get WSL monitor statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WslMonGetStatistics(
    _Out_ PWSL_STATISTICS Statistics
    );
