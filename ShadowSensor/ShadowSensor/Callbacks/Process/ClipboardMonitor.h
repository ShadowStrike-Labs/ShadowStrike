/*++
    ShadowStrike Next-Generation Antivirus
    Module: ClipboardMonitor.h - Kernel-side clipboard abuse detection

    Purpose: Heuristic detection of clipboard data theft and abuse patterns.
    Since direct clipboard access monitoring requires user-mode hooks
    (clipboard is managed by csrss.exe/win32k.sys), this kernel module
    detects clipboard abuse through observable process behavior patterns:

    Detection Strategies:
    1. Process image analysis — known clipboard stealers (clip.exe abuse,
       powershell Get-Clipboard, suspicious clipboard-related imports)
    2. Rapid file writes to clipboard cache paths (%TEMP%, %LocalAppData%)
    3. Cross-process handle duplication targeting clipboard-owning processes
    4. Behavioral correlation — clipboard access + network exfiltration pattern
    5. Command-line patterns indicating clipboard harvesting

    MITRE ATT&CK: T1115 (Clipboard Data)

    IRQL Contracts:
    - CbMonInitialize:            PASSIVE_LEVEL only
    - CbMonShutdown:              PASSIVE_LEVEL only
    - CbMonCheckProcessCreate:    PASSIVE_LEVEL (process notify context)
    - CbMonCheckFileWrite:        <= APC_LEVEL (minifilter callback context)
    - CbMonGetStatistics:         <= APC_LEVEL

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>

// ============================================================================
// Pool Tags
// ============================================================================

#define CBMON_POOL_TAG          'bMbC'   // CbMb

// ============================================================================
// Clipboard Abuse Indicators
// ============================================================================

typedef enum _CBMON_INDICATOR {
    CbIndicator_None                    = 0x00000000,
    CbIndicator_ClipboardCommandLine    = 0x00000001,  // Get-Clipboard, clip.exe piping
    CbIndicator_KnownStealerImage       = 0x00000002,  // Known clipboard stealer PE names
    CbIndicator_RapidTempFileWrites     = 0x00000004,  // Rapid file writes to temp/appdata
    CbIndicator_SuspiciousImports       = 0x00000008,  // OpenClipboard/GetClipboardData imports
    CbIndicator_NetworkAfterClipboard   = 0x00000010,  // Network activity after clipboard access
    CbIndicator_CrossProcessHandle      = 0x00000020,  // Handle dup to clipboard owner
    CbIndicator_EncodedClipboardCmd     = 0x00000040,  // Base64 encoded clipboard commands
} CBMON_INDICATOR;

// ============================================================================
// Statistics
// ============================================================================

typedef struct _CBMON_STATISTICS {
    volatile LONG64 TotalProcessesChecked;
    volatile LONG64 SuspiciousDetections;
    volatile LONG64 CommandLineMatches;
    volatile LONG64 FileWriteMatches;
    volatile LONG64 CrossProcessMatches;
} CBMON_STATISTICS, *PCBMON_STATISTICS;

// ============================================================================
// Public API
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbMonInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbMonShutdown(VOID);

/**
 * @brief Check process creation for clipboard theft indicators.
 *
 * Analyzes the process image name and command line for patterns associated
 * with clipboard data harvesting (T1115).
 *
 * @param ProcessId  New process ID.
 * @param CreateInfo Process creation info from PsSetCreateProcessNotifyRoutineEx.
 * @return Bitmask of CBMON_INDICATOR flags detected, 0 if clean.
 */
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
CbMonCheckProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

/**
 * @brief Check file write for clipboard cache exfiltration pattern.
 *
 * Monitors writes to temp/appdata paths that match clipboard dumping behavior:
 * rapid small writes to .txt/.log files from processes with clipboard indicators.
 *
 * @param ProcessId     Requestor PID.
 * @param FileName      File being written to.
 * @return TRUE if write matches clipboard exfiltration pattern.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
CbMonCheckFileWrite(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CbMonGetStatistics(
    _Out_ PCBMON_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
