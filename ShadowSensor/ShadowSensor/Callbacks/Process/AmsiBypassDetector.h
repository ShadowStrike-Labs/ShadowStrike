/*++
    ShadowStrike Next-Generation Antivirus
    Module: AmsiBypassDetector.h - Kernel-side AMSI bypass detection

    Detects attempts to bypass the Antimalware Scan Interface (AMSI) by:
    - Patching AmsiScanBuffer/AmsiOpenSession function prologues
    - Modifying amsi.dll memory protection (RW/RWX transitions)
    - Unloading or preventing amsi.dll load
    - Overwriting AMSI context structures
    - Patching ETW provider functions (EtwEventWrite) to blind telemetry

    This module operates purely as a DETECTOR — it does NOT implement
    an AMSI scan provider. The actual AMSI provider runs in user-space.

    MITRE ATT&CK:
    - T1562.001: Disable or Modify Tools (AMSI bypass)
    - T1562.006: Indicator Blocking (ETW patching)

    Architecture:
    - Uses NtdllIntegrity-style clean baseline comparison
    - Integrates with ImageNotify for amsi.dll load interception
    - Integrates with MemoryMonitor for protection change detection
    - Reports via BehaviorEvent_AMSIBypass (0x0504) existing event

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define ABD_POOL_TAG_MAIN       'mBAs'  // sABm - Main structure
#define ABD_POOL_TAG_PROC       'pBAs'  // sABp - Process state
#define ABD_POOL_TAG_BASELINE   'bBAs'  // sABb - Clean baseline copy
#define ABD_POOL_TAG_TEMP       'tBAs'  // sABt - Temporary buffers

// ============================================================================
// CONSTANTS
// ============================================================================

#define ABD_MAX_TRACKED_PROCESSES   256
#define ABD_PROLOGUE_SIZE           16
#define ABD_HASH_SIZE               32      // SHA-256
#define ABD_FUNCTION_NAME_MAX       64
#define ABD_MAX_CRITICAL_FUNCTIONS  8
#define ABD_SCAN_INTERVAL_100NS     (-(LONGLONG)30 * 10000000LL)  // 30 seconds

//
// CAS lifecycle
//
#define ABD_STATE_UNINITIALIZED     0
#define ABD_STATE_INITIALIZING      1
#define ABD_STATE_READY             2
#define ABD_STATE_SHUTTING_DOWN     3

// ============================================================================
// BYPASS TECHNIQUE CLASSIFICATION
// ============================================================================

typedef enum _ABD_BYPASS_TYPE {
    AbdBypass_None                  = 0,
    AbdBypass_PatchAmsiScanBuffer,      // AmsiScanBuffer prologue patched (ret/mov eax)
    AbdBypass_PatchAmsiOpenSession,     // AmsiOpenSession prologue patched
    AbdBypass_PatchAmsiInitialize,      // AmsiInitialize patched
    AbdBypass_AmsiDllUnloaded,          // amsi.dll forcibly unloaded
    AbdBypass_AmsiDllNotLoaded,         // amsi.dll prevented from loading
    AbdBypass_AmsiContextOverwrite,     // AMSI context pointer zeroed
    AbdBypass_MemoryProtectionChange,   // amsi.dll .text made writable
    AbdBypass_EtwEventWritePatch,       // EtwEventWrite patched (ETW blinding)
    AbdBypass_EtwProviderDisabled,      // ETW provider disabled via registry
    AbdBypass_InlineHook,               // Generic inline hook on AMSI function
    AbdBypass_Max
} ABD_BYPASS_TYPE;

// ============================================================================
// DETECTION RESULT
// ============================================================================

typedef struct _ABD_DETECTION {
    ABD_BYPASS_TYPE BypassType;
    HANDLE ProcessId;
    PVOID TargetAddress;            // Address of patched function
    UCHAR OriginalBytes[ABD_PROLOGUE_SIZE];
    UCHAR CurrentBytes[ABD_PROLOGUE_SIZE];
    LARGE_INTEGER DetectionTime;
    CHAR FunctionName[ABD_FUNCTION_NAME_MAX];
} ABD_DETECTION, *PABD_DETECTION;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _ABD_STATISTICS {
    volatile LONG64 ProcessesMonitored;
    volatile LONG64 AmsiLoadsObserved;
    volatile LONG64 BypassesDetected;
    volatile LONG64 PatchDetections;
    volatile LONG64 ProtectionChangeDetections;
    volatile LONG64 EtwPatchDetections;
    volatile LONG64 ScansPerformed;
} ABD_STATISTICS, *PABD_STATISTICS;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

/**
 * @brief Initialize AMSI bypass detector.
 *        Loads clean amsi.dll baseline from System32.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdInitialize(
    VOID
    );

/**
 * @brief Shutdown AMSI bypass detector.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdShutdown(
    VOID
    );

/**
 * @brief Check if detector is active.
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
AbdIsActive(
    VOID
    );

// ============================================================================
// PUBLIC API — IMAGE LOAD INTEGRATION
// ============================================================================

/**
 * @brief Called from ImageNotify callback when a DLL is loaded.
 *        Checks if the loaded module is amsi.dll and records its base address.
 *
 * @param ProcessId     Process ID where image was loaded.
 * @param ImageBase     Base address of the loaded image.
 * @param ImageSize     Size of the loaded image.
 * @param ImageName     Full path of the image (e.g., \Device\HarddiskVolume3\Windows\System32\amsi.dll).
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdNotifyImageLoad(
    _In_ HANDLE ProcessId,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ PUNICODE_STRING ImageName
    );

// ============================================================================
// PUBLIC API — INTEGRITY SCAN
// ============================================================================

/**
 * @brief Scan a process for AMSI bypass indicators.
 *        Compares amsi.dll function prologues against clean baseline.
 *
 * @param ProcessId     Process to scan.
 * @param Detection     Receives detection result if bypass found.
 *
 * @return STATUS_SUCCESS if scan completed (check Detection->BypassType for result).
 *         STATUS_NOT_FOUND if process has no amsi.dll loaded.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdScanProcess(
    _In_ HANDLE ProcessId,
    _Out_ PABD_DETECTION Detection
    );

/**
 * @brief Check if a memory protection change targets amsi.dll.
 *        Called from MemoryMonitor when VirtualProtect is observed.
 *
 * @param ProcessId     Target process.
 * @param BaseAddress   Region base address.
 * @param RegionSize    Region size.
 * @param OldProtection Previous protection flags.
 * @param NewProtection New protection flags.
 *
 * @return TRUE if this targets amsi.dll text section (indicates bypass attempt).
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
AbdCheckProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    );

// ============================================================================
// PUBLIC API — STATISTICS
// ============================================================================

/**
 * @brief Get detector statistics.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AbdGetStatistics(
    _Out_ PABD_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
