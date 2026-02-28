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
/*++
===============================================================================
ShadowStrike NGAV - HEAVEN'S GATE DETECTOR HEADER
===============================================================================

@file HeavensGateDetector.h
@brief Enterprise-grade Heaven's Gate (WoW64 abuse) detection for kernel EDR.

Provides detection of 32-to-64 bit transition abuse in WoW64 processes:
- Heaven's Gate detection (manual CS segment switching)
- Hell's Gate detection (dynamic SSN resolution from clean ntdll)
- Halo's Gate detection (neighbor syscall walking)
- Legitimate WoW64 transition validation
- Syscall origin verification

All public APIs callable at IRQL <= APC_LEVEL unless otherwise noted.
Callback routines are invoked at PASSIVE_LEVEL.

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define HGD_POOL_TAG 'DGHH'

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _HGD_GATE_TYPE {
    HgdGate_None = 0,
    HgdGate_HeavensGate,                // 32 -> 64 bit manual transition
    HgdGate_HellsGate,                  // Dynamic SSN from unhook
    HgdGate_WoW64Transition,            // Legitimate wow64cpu.dll
    HgdGate_ManualTransition,           // Handcrafted far call / RETF
} HGD_GATE_TYPE;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

typedef struct _HGD_TRANSITION_INFO HGD_TRANSITION_INFO, *PHGD_TRANSITION_INFO;

// ============================================================================
// CALLBACK TYPE
// ============================================================================

//
// Detection callback signature.
// Called at IRQL <= APC_LEVEL with no locks held.
// The Transition pointer is valid only for the duration of the callback.
// Callbacks MUST NOT block for extended periods or acquire locks that
// could be held by HGD callers.
//
typedef VOID
(NTAPI *HGD_DETECTION_CALLBACK)(
    _In_ PHGD_TRANSITION_INFO Transition,
    _In_opt_ PVOID Context
    );

// ============================================================================
// PUBLIC STRUCTURES
// ============================================================================

//
// Transition information record - deep-copied, caller-owned.
// Returned by HgdAnalyzeTransition and HgdGetTransitions.
// Must be freed with HgdFreeTransition.
//
struct _HGD_TRANSITION_INFO {
    HANDLE ProcessId;
    HANDLE ThreadId;

    HGD_GATE_TYPE Type;

    //
    // Source context (32-bit side)
    //
    ULONG SourceCS;
    PVOID SourceRIP;
    PVOID SourceRSP;

    //
    // Target context (64-bit side)
    //
    ULONG TargetCS;
    PVOID TargetRIP;
    PVOID TargetRSP;

    //
    // Syscall being executed
    //
    ULONG SyscallNumber;
    ULONG64 SyscallArgs[8];

    //
    // Module info - embedded buffer, no dangling pointer
    //
    WCHAR SourceModuleName[64];
    USHORT SourceModuleNameLength;       // In bytes, excluding null
    BOOLEAN IsFromWow64;

    ULONG SuspicionScore;
    LARGE_INTEGER Timestamp;
};

//
// Opaque detector handle.
// Internal structure is hidden from callers.
//
typedef struct _HGD_DETECTOR HGD_DETECTOR, *PHGD_DETECTOR;

//
// Detector statistics (read atomically).
//
typedef struct _HGD_STATISTICS {
    LONG64 TransitionsDetected;
    LONG64 LegitimateTransitions;
    LONG64 SuspiciousTransitions;
    LARGE_INTEGER StartTime;
} HGD_STATISTICS, *PHGD_STATISTICS;

// ============================================================================
// LIFECYCLE APIs
// ============================================================================

//
// Initializes the Heaven's Gate detector subsystem.
// Must be called at IRQL == PASSIVE_LEVEL.
// The work queue subsystem (ShadowStrikeWorkQueueInitialize) must be
// initialized before calling this function.
//
// @param Detector  Receives opaque pointer to initialized detector.
// @return STATUS_SUCCESS on success.
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HgdInitialize(
    _Out_ PHGD_DETECTOR* Detector
    );

//
// Shuts down the detector and frees all resources.
// Safe to call with NULL. Blocks until all pending work items complete.
//
// @param Detector  Detector instance to shutdown. Set to NULL on return.
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
HgdShutdown(
    _Inout_ PHGD_DETECTOR Detector
    );

// ============================================================================
// DETECTION APIs
// ============================================================================

//
// Analyzes a potential Heaven's Gate transition.
// Returns a deep-copied transition record that the caller owns.
// The caller MUST free the record with HgdFreeTransition.
//
// @param Detector          Detector instance.
// @param ProcessId         Process ID where transition occurred.
// @param ThreadId          Thread ID.
// @param TransitionAddress Address of transition code (user-mode).
// @param CodeSnapshot      Pre-read code bytes at TransitionAddress.
// @param CodeSnapshotSize  Size of CodeSnapshot buffer in bytes.
// @param Transition        Receives caller-owned transition record.
// @return STATUS_SUCCESS on success.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdAnalyzeTransition(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID TransitionAddress,
    _In_reads_bytes_(CodeSnapshotSize) PUCHAR CodeSnapshot,
    _In_ ULONG CodeSnapshotSize,
    _Out_ PHGD_TRANSITION_INFO* Transition
    );

//
// Checks if an address is a legitimate WoW64 transition point
// for the current process.
//
// @param Detector     Detector instance.
// @param Address      Address to check.
// @param IsLegitimate Receives TRUE if legitimate WoW64 address.
// @return STATUS_SUCCESS on success.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdIsLegitimateWow64(
    _In_ PHGD_DETECTOR Detector,
    _In_ PVOID Address,
    _Out_ PBOOLEAN IsLegitimate
    );

//
// Detects if a syscall originated from a suspicious location.
//
// @param Detector      Detector instance.
// @param ProcessId     Process ID.
// @param SyscallNumber Syscall number being invoked.
// @param ReturnAddress Return address of syscall.
// @param IsSuspicious  Receives TRUE if suspicious.
// @param GateType      Optional: receives detected gate type.
// @return STATUS_SUCCESS on success.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdDetectSyscallOrigin(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ ULONG SyscallNumber,
    _In_ PVOID ReturnAddress,
    _Out_ PBOOLEAN IsSuspicious,
    _Out_opt_ HGD_GATE_TYPE* GateType
    );

// ============================================================================
// QUERY APIs
// ============================================================================

//
// Gets deep-copied transition records for a specific process.
// Each element of the output array is a separately allocated record
// that MUST be freed by calling HgdFreeTransition on each.
//
// @param Detector    Detector instance.
// @param ProcessId   Process ID to query.
// @param Transitions Array to receive transition pointers (caller-allocated).
// @param Max         Maximum transitions to return.
// @param Count       Receives number of transitions returned.
// @return STATUS_SUCCESS on success.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdGetTransitions(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(Max, *Count) PHGD_TRANSITION_INFO* Transitions,
    _In_ ULONG Max,
    _Out_ PULONG Count
    );

//
// Frees a caller-owned transition record.
// Safe to call with NULL.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
HgdFreeTransition(
    _In_opt_ PHGD_TRANSITION_INFO Transition
    );

//
// Gets detector statistics (lock-free, safe at any IRQL).
//
// @param Detector   Detector instance.
// @param Statistics Receives statistics snapshot.
// @return STATUS_SUCCESS on success.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
HgdGetStatistics(
    _In_ PHGD_DETECTOR Detector,
    _Out_ PHGD_STATISTICS Statistics
    );

//
// Gets detection flags and suspicion score for a process.
//
// @param Detector       Detector instance.
// @param ProcessId      Process ID.
// @param Flags          Receives process flags (HGD_PROC_FLAG_*).
// @param SuspicionScore Optional: receives suspicion score.
// @return STATUS_SUCCESS on success, STATUS_NOT_FOUND if not tracked.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdGetProcessFlags(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PULONG Flags,
    _Out_opt_ PULONG SuspicionScore
    );

// ============================================================================
// MANAGEMENT APIs
// ============================================================================

//
// Refreshes system WoW64 module addresses.
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HgdRefreshWow64Addresses(
    _In_ PHGD_DETECTOR Detector
    );

//
// Adds an address to the known-good whitelist for a process.
//
// @param Detector  Detector instance.
// @param ProcessId Process ID.
// @param Address   Address to whitelist.
// @return STATUS_SUCCESS on success, STATUS_QUOTA_EXCEEDED if list full.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdAddKnownGoodAddress(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address
    );

//
// Removes process context when process exits.
// Should be called from process-exit notification callback.
//
_IRQL_requires_max_(APC_LEVEL)
VOID
HgdRemoveProcessContext(
    _In_ PHGD_DETECTOR Detector,
    _In_ HANDLE ProcessId
    );

//
// Registers a detection callback.
// Callbacks are invoked at PASSIVE_LEVEL.
//
// @param Detector Detector instance.
// @param Callback Callback function (see HGD_DETECTION_CALLBACK).
// @param Context  Optional user context passed to callback.
// @return STATUS_SUCCESS on success, STATUS_QUOTA_EXCEEDED if slots full.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HgdRegisterCallback(
    _In_ PHGD_DETECTOR Detector,
    _In_ HGD_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//
// Unregisters a detection callback.
//
_IRQL_requires_max_(APC_LEVEL)
VOID
HgdUnregisterCallback(
    _In_ PHGD_DETECTOR Detector,
    _In_ HGD_DETECTION_CALLBACK Callback
    );

// ============================================================================
// PROCESS FLAGS
// ============================================================================

#define HGD_PROC_FLAG_MONITORED         0x00000001
#define HGD_PROC_FLAG_HIGH_RISK         0x00000002
#define HGD_PROC_FLAG_HEAVENS_GATE      0x00000004
#define HGD_PROC_FLAG_HELLS_GATE        0x00000008
#define HGD_PROC_FLAG_BLOCKED           0x00000010

#ifdef __cplusplus
}
#endif
