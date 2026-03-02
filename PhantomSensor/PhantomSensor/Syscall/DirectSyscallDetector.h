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
    ShadowStrike Next-Generation Antivirus
    Module: DirectSyscallDetector.h - Direct syscall abuse detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

#define DSD_POOL_TAG 'DSSD'

typedef enum _DSD_TECHNIQUE {
    DsdTechnique_None = 0,
    DsdTechnique_DirectSyscall,         // mov eax, SSDT#; syscall
    DsdTechnique_IndirectSyscall,       // jmp to ntdll syscall stub
    DsdTechnique_Manual,                // Manual SSDT resolution
    DsdTechnique_HeavensGate,           // 32->64 bit transition
    DsdTechnique_HellsGate,             // Dynamic SSN resolution
    DsdTechnique_HalosGate,             // Neighbor syscall walking
    DsdTechnique_TartarusGate,          // Exception-based resolution
    DsdTechnique_SysWhispers,           // SysWhispers patterns
} DSD_TECHNIQUE, *PDSD_TECHNIQUE;

//
// DSD_DETECTION is an opaque snapshot returned to callers.
// The caller owns the pointer and must free it with DsdFreeDetection.
// The detection is NOT linked to any internal list once returned.
//
typedef struct _DSD_DETECTION {
    HANDLE ProcessId;
    HANDLE ThreadId;

    DSD_TECHNIQUE Technique;
    ULONG SyscallNumber;
    PVOID CallerAddress;
    PVOID StackPointer;

    PVOID ReturnAddresses[16];
    ULONG ReturnAddressCount;
    BOOLEAN CallFromNtdll;
    BOOLEAN CallFromKnownModule;

    WCHAR CallerModuleName[260];
    ULONG64 CallerModuleBase;
    ULONG64 CallerModuleSize;
    ULONG64 CallerOffset;

    ULONG SuspicionScore;
    LARGE_INTEGER Timestamp;
} DSD_DETECTION, *PDSD_DETECTION;

//
// Opaque detector handle. Internal layout is private to the .c file.
//
typedef struct _DSD_DETECTOR DSD_DETECTOR, *PDSD_DETECTOR;

typedef struct _DSD_DETECTOR_STATS {
    volatile LONG64 SyscallsAnalyzed;
    volatile LONG64 DirectCalls;
    volatile LONG64 IndirectCalls;
    volatile LONG64 HeavensGateCalls;
    volatile LONG64 HellsGateCalls;
    volatile LONG64 HalosGateCalls;
    volatile LONG64 TartarusGateCalls;
    volatile LONG64 SysWhispersCalls;
    volatile LONG64 RateLimitDrops;
    LARGE_INTEGER StartTime;
} DSD_DETECTOR_STATS, *PDSD_DETECTOR_STATS;

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdInitialize(
    _Out_ PDSD_DETECTOR* Detector
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
DsdShutdown(
    _Inout_ PDSD_DETECTOR Detector
    );

//
// Analyzes a syscall caller address for direct/indirect syscall abuse.
// Returns STATUS_SUCCESS with *Detection != NULL if a suspicious pattern is found.
// Returns STATUS_NO_MORE_ENTRIES if the address is whitelisted (no detection).
// Returns STATUS_NOT_FOUND if no suspicious pattern is detected.
// Caller must free *Detection with DsdFreeDetection on success.
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdAnalyzeSyscall(
    _In_ PDSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID CallerAddress,
    _In_ ULONG SyscallNumber,
    _Out_ PDSD_DETECTION* Detection
    );

//
// Detects the evasion technique used in a block of instruction bytes.
// ProcessId is required to resolve relative jumps against NTDLL.
// CallerRip is the actual instruction pointer for displacement calculation.
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdDetectTechnique(
    _In_ PDSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID CallerRip,
    _In_ PVOID Address,
    _In_ ULONG Length,
    _Out_ PDSD_TECHNIQUE Technique
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DsdValidateCallstack(
    _In_ PDSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsValid,
    _Out_opt_ PDSD_TECHNIQUE Technique
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
DsdFreeDetection(
    _In_ _Post_ptr_invalid_ PDSD_DETECTION Detection
    );

#ifdef __cplusplus
}
#endif
