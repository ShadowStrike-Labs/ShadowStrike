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
    Module: CallstackAnalyzer.h - Call stack analysis and validation

    Purpose:
        Enterprise-grade call stack capture, unwinding, and anomaly detection
        for kernel-mode EDR. Detects stack spoofing, ROP chains, stack pivoting,
        unbacked code execution, and direct syscall abuse.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntddk.h>

#define CSA_POOL_TAG 'ASAC'
#define CSA_MAX_FRAMES 64
#define CSA_MAX_MODULE_NAME_CCH 260

typedef enum _CSA_FRAME_TYPE {
    CsaFrame_Unknown = 0,
    CsaFrame_Kernel,
    CsaFrame_User,
    CsaFrame_Transition,
    CsaFrame_SystemCall,
} CSA_FRAME_TYPE;

typedef enum _CSA_ANOMALY {
    CsaAnomaly_None                 = 0x00000000,
    CsaAnomaly_UnbackedCode         = 0x00000001,
    CsaAnomaly_RWXMemory            = 0x00000002,
    CsaAnomaly_StackPivot           = 0x00000004,
    CsaAnomaly_MissingFrames        = 0x00000008,
    CsaAnomaly_SpoofedFrames        = 0x00000010,
    CsaAnomaly_UnknownModule        = 0x00000020,
    CsaAnomaly_DirectSyscall        = 0x00000040,
    CsaAnomaly_ReturnGadget         = 0x00000080,
} CSA_ANOMALY, *PCSA_ANOMALY;

typedef struct _CSA_STACK_FRAME {
    PVOID ReturnAddress;
    PVOID FramePointer;
    PVOID StackPointer;

    //
    // Module info — name is deep-copied, buffer is owned by this frame
    //
    PVOID ModuleBase;
    WCHAR ModuleNameBuffer[CSA_MAX_MODULE_NAME_CCH];
    UNICODE_STRING ModuleName;
    ULONG64 OffsetInModule;

    CSA_FRAME_TYPE Type;
    BOOLEAN IsBackedByImage;
    BOOLEAN IsWow64Frame;
    ULONG MemoryProtection;

    CSA_ANOMALY AnomalyFlags;
} CSA_STACK_FRAME, *PCSA_STACK_FRAME;

typedef struct _CSA_CALLSTACK {
    HANDLE ProcessId;
    HANDLE ThreadId;

    CSA_STACK_FRAME Frames[CSA_MAX_FRAMES];
    ULONG FrameCount;

    CSA_ANOMALY AggregatedAnomalies;
    ULONG SuspicionScore;
    BOOLEAN IsWow64Process;

    LARGE_INTEGER CaptureTime;
} CSA_CALLSTACK, *PCSA_CALLSTACK;

typedef struct _CSA_ANALYZER {
    BOOLEAN Initialized;

    //
    // Module cache — guarded by ModuleLock (EX_PUSH_LOCK).
    // Callers must use KeEnterCriticalRegion / KeLeaveCriticalRegion.
    //
    LIST_ENTRY ModuleCache;
    EX_PUSH_LOCK ModuleLock;

    //
    // Operational reference count. Shutdown waits for all refs to drain.
    //
    volatile LONG RefCount;
    KEVENT ZeroRefEvent;

    struct {
        volatile LONG64 StacksCaptured;
        volatile LONG64 AnomaliesFound;
        LARGE_INTEGER StartTime;
    } Stats;
} CSA_ANALYZER, *PCSA_ANALYZER;

//
// Public API — all require IRQL <= PASSIVE_LEVEL
//

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CsaInitialize(
    _Out_ PCSA_ANALYZER* Analyzer
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CsaShutdown(
    _Inout_ PCSA_ANALYZER Analyzer
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CsaCaptureCallstack(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PCSA_CALLSTACK* Callstack
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CsaAnalyzeCallstack(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ PCSA_CALLSTACK Callstack,
    _Out_ PCSA_ANOMALY Anomalies,
    _Out_ PULONG Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CsaValidateReturnAddresses(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ PCSA_CALLSTACK Callstack,
    _Out_ PBOOLEAN AllValid
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CsaDetectStackPivot(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsPivoted
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CsaFreeCallstack(
    _In_ PCSA_CALLSTACK Callstack
    );

//
// Process exit notification — must be called from process notify callback
// when a process is terminating to invalidate stale cache entries.
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CsaOnProcessExit(
    _In_ PCSA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId
    );

#ifdef __cplusplus
}
#endif
