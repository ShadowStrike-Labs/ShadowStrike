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
    Module: ETWProvider.c

    Purpose: Enterprise-grade ETW (Event Tracing for Windows) provider for
             high-performance telemetry streaming, SIEM integration, and
             real-time diagnostics.

    Architecture:
    - Kernel-mode ETW provider registration via EtwRegister
    - Event descriptor-based event writing with per-event-ID descriptors
    - Per-severity rate limiting (CRITICAL events are never dropped)
    - Atomic enable-state snapshot for lock-free enable tracking
    - State-machine lifecycle for safe init/shutdown under concurrency
    - All PCWSTR parameters bounded by wcsnlen to prevent runaway scans
    - Lookaside buffer dynamically sized to largest event struct (compile-time)
    - In-flight writer reference counting with bounded drain timeout
    - ReadAcquire-based state checks for ARM64 memory ordering correctness

    Version: 2.1.0 — Full fix pass addressing all CRITICAL/HIGH/MEDIUM/LOW
    issues from the v2.0.0 security review.

    Copyright (c) ShadowStrike Team
--*/

#include <initguid.h>
#include "ETWProvider.h"
#include "../Utilities/MemoryUtils.h"

//
// MmGetSessionId is exported by ntoskrnl.exe since Windows Vista but
// not always declared in WDK headers depending on NTDDI_VERSION settings.
//
#ifndef MmGetSessionId
NTKERNELAPI ULONG MmGetSessionId(_In_ PEPROCESS Process);
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EtwProviderInitialize)
#pragma alloc_text(PAGE, EtwProviderShutdown)
#endif

// ============================================================================
// GUID Definition (defined here via INITGUID; header declares extern)
// ============================================================================

// {3A5E8B2C-7D4F-4E6A-9C1B-8D0F2E3A4B5C}
DEFINE_GUID(SHADOWSTRIKE_ETW_PROVIDER_GUID,
    0x3a5e8b2c, 0x7d4f, 0x4e6a, 0x9c, 0x1b, 0x8d, 0x0f, 0x2e, 0x3a, 0x4b, 0x5c);

// ============================================================================
// Internal Constants
// ============================================================================

#define ETW_MAX_EVENTS_PER_SECOND           10000
#define ETW_LOOKASIDE_DEPTH                 256
#define ETW_RATE_LIMIT_WINDOW_100NS         (10000000LL)  // 1 second in 100ns units
#define ETW_MAX_DIAGNOSTIC_MESSAGE_CHARS    512
#define ETW_SHUTDOWN_DRAIN_SPIN_LIMIT       1000
#define ETW_SHUTDOWN_DRAIN_SLEEP_MS         1
#define ETW_SHUTDOWN_MAX_DRAIN_100NS        (10000000LL * 10)  // 10 seconds max drain

// ============================================================================
// Global State
// ============================================================================

static ETW_PROVIDER_GLOBALS g_EtwGlobals = { 0 };

// ============================================================================
// Forward Declarations
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
EtwpCheckRateLimit(
    _In_ UCHAR EventLevel
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpUpdateStatistics(
    _In_ ULONG EventSize,
    _In_ BOOLEAN Success
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpFillCommonHeader(
    _Out_ PETW_EVENT_COMMON Common,
    _In_ UINT32 ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
EtwpWriteEvent(
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID NTAPI
EtwpEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    );

static BOOLEAN
EtwpAcquireWriterRef(
    VOID
    );

static VOID
EtwpReleaseWriterRef(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpCopyBoundedString(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCWSTR Src,
    _In_ ULONG MaxSrcChars
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpCopyUnicodeStringBounded(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCUNICODE_STRING Src
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PCEVENT_DESCRIPTOR
EtwpGetSecurityDescriptor(
    _In_ UINT32 AlertType
    );

// ============================================================================
// Event Descriptors
// ============================================================================

//
// Process Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_ProcessCreate = {
    EtwEventId_ProcessCreate,       // Id
    0,                              // Version
    0,                              // Channel
    ETW_LEVEL_INFORMATIONAL,        // Level
    0,                              // Opcode
    0,                              // Task
    ETW_KEYWORD_PROCESS             // Keyword
};

static const EVENT_DESCRIPTOR EtwDescriptor_ProcessTerminate = {
    EtwEventId_ProcessTerminate,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_PROCESS
};

static const EVENT_DESCRIPTOR EtwDescriptor_ProcessSuspicious = {
    EtwEventId_ProcessSuspicious,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_PROCESS | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_ProcessBlocked = {
    EtwEventId_ProcessBlocked,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_PROCESS | ETW_KEYWORD_THREAT
};

//
// File Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_FileCreate = {
    EtwEventId_FileCreate,
    0, 0, ETW_LEVEL_VERBOSE, 0, 0, ETW_KEYWORD_FILE
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileWrite = {
    EtwEventId_FileWrite,
    0, 0, ETW_LEVEL_VERBOSE, 0, 0, ETW_KEYWORD_FILE
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileScanResult = {
    EtwEventId_FileScanResult,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileBlocked = {
    EtwEventId_FileBlocked,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileQuarantined = {
    EtwEventId_FileQuarantined,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT
};

//
// Network Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_NetworkConnect = {
    EtwEventId_NetworkConnect,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_NETWORK
};

static const EVENT_DESCRIPTOR EtwDescriptor_NetworkListen = {
    EtwEventId_NetworkListen,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_NETWORK
};

static const EVENT_DESCRIPTOR EtwDescriptor_DnsQuery = {
    EtwEventId_DnsQuery,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_NETWORK
};

static const EVENT_DESCRIPTOR EtwDescriptor_NetworkBlocked = {
    EtwEventId_NetworkBlocked,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_ExfiltrationDetected = {
    EtwEventId_ExfiltrationDetected,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT | ETW_KEYWORD_SECURITY
};

static const EVENT_DESCRIPTOR EtwDescriptor_C2Detected = {
    EtwEventId_C2Detected,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT | ETW_KEYWORD_SECURITY
};

//
// Behavioral Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_BehaviorAlert = {
    EtwEventId_BehaviorAlert,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_AttackChainStarted = {
    EtwEventId_AttackChainStarted,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_AttackChainUpdated = {
    EtwEventId_AttackChainUpdated,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_AttackChainCompleted = {
    EtwEventId_AttackChainCompleted,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_MitreDetection = {
    EtwEventId_MitreDetection,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

//
// Security Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_TamperAttempt = {
    EtwEventId_TamperAttempt,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_EvasionAttempt = {
    EtwEventId_EvasionAttempt,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_DirectSyscall = {
    EtwEventId_DirectSyscall,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_SECURITY
};

static const EVENT_DESCRIPTOR EtwDescriptor_PrivilegeEscalation = {
    EtwEventId_PrivilegeEscalation,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_CredentialAccess = {
    EtwEventId_CredentialAccess,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT
};

//
// Diagnostic Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_DriverStarted = {
    EtwEventId_DriverStarted,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

static const EVENT_DESCRIPTOR EtwDescriptor_DriverStopping = {
    EtwEventId_DriverStopping,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

static const EVENT_DESCRIPTOR EtwDescriptor_Heartbeat = {
    EtwEventId_Heartbeat,
    0, 0, ETW_LEVEL_VERBOSE, 0, 0, ETW_KEYWORD_DIAGNOSTIC | ETW_KEYWORD_TELEMETRY
};

static const EVENT_DESCRIPTOR EtwDescriptor_PerformanceStats = {
    EtwEventId_PerformanceStats,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC | ETW_KEYWORD_TELEMETRY
};

static const EVENT_DESCRIPTOR EtwDescriptor_ComponentHealth = {
    EtwEventId_ComponentHealth,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

static const EVENT_DESCRIPTOR EtwDescriptor_Error = {
    EtwEventId_Error,
    0, 0, ETW_LEVEL_ERROR, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

// ============================================================================
// Initialization / Shutdown
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwProviderInitialize(
    VOID
    )
/*++

Routine Description:

    Initializes the ETW provider subsystem. Uses a state machine with
    InterlockedCompareExchange to prevent double-initialization races.

Return Value:

    STATUS_SUCCESS on success.
    STATUS_ALREADY_INITIALIZED if already initialized.
    STATUS_UNSUCCESSFUL if state transition fails.

--*/
{
    NTSTATUS status;
    LONG previousState;

    PAGED_CODE();

    //
    // Atomic state transition: UNINITIALIZED -> INITIALIZING
    //
    previousState = InterlockedCompareExchange(
        &g_EtwGlobals.State,
        EtwState_Initializing,
        EtwState_Uninitialized
        );

    if (previousState == EtwState_Ready) {
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState != EtwState_Uninitialized) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // We now own the initialization path exclusively.
    // Zero all fields except State to avoid a window where another thread
    // could see State transiently become EtwState_Uninitialized and race
    // into a second initialization. State is already INITIALIZING from
    // the CAS above and remains so throughout.
    //
    RtlZeroMemory(
        (PUCHAR)&g_EtwGlobals + FIELD_OFFSET(ETW_PROVIDER_GLOBALS, Reserved0),
        sizeof(ETW_PROVIDER_GLOBALS) - FIELD_OFFSET(ETW_PROVIDER_GLOBALS, Reserved0)
        );

    //
    // Register the ETW provider
    //
    status = EtwRegister(
        &SHADOWSTRIKE_ETW_PROVIDER_GUID,
        EtwpEnableCallback,
        NULL,
        &g_EtwGlobals.ProviderHandle
        );

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_EtwGlobals.State, EtwState_Uninitialized);
        return status;
    }

    //
    // Initialize lookaside list for event buffers.
    // ETW_EVENT_BUFFER_SIZE is computed at compile time as the maximum
    // of all event structure sizes, rounded up to 256-byte boundary.
    //
    ExInitializeNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        (ULONG)ETW_EVENT_BUFFER_SIZE,
        ETW_POOL_TAG_BUFFER,
        ETW_LOOKASIDE_DEPTH
        );

    //
    // Initialize rate limiting
    //
    g_EtwGlobals.MaxEventsPerSecond = ETW_MAX_EVENTS_PER_SECOND;
    InterlockedExchange(&g_EtwGlobals.EventsThisSecond, 0);

    {
        LARGE_INTEGER now;
        KeQuerySystemTimePrecise(&now);
        InterlockedExchange64(&g_EtwGlobals.CurrentSecondStart, now.QuadPart);
    }

    //
    // Statistics are already zeroed by RtlZeroMemory above.
    // In-flight writer count starts at 0.
    //

    //
    // Enabled = FALSE. Will be set by enable callback when a consumer attaches.
    //
    InterlockedExchange(&g_EtwGlobals.Enabled, FALSE);

    //
    // Transition: INITIALIZING -> READY (publish to other threads)
    //
    MemoryBarrier();
    InterlockedExchange(&g_EtwGlobals.State, EtwState_Ready);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
EtwProviderShutdown(
    VOID
    )
/*++

Routine Description:

    Shuts down the ETW provider. Uses state machine to prevent races.
    Drains in-flight writers before tearing down resources.

--*/
{
    LONG previousState;
    ULONG spinCount;
    LONG64 drainStartTime;
    LARGE_INTEGER delay;

    PAGED_CODE();

    //
    // Atomic state transition: READY -> SHUTTING_DOWN
    //
    previousState = InterlockedCompareExchange(
        &g_EtwGlobals.State,
        EtwState_ShuttingDown,
        EtwState_Ready
        );

    if (previousState != EtwState_Ready) {
        return;
    }

    //
    // Disable event writing immediately. New writers will see this
    // and bail out before acquiring a writer ref.
    //
    InterlockedExchange(&g_EtwGlobals.Enabled, FALSE);
    MemoryBarrier();

    //
    // Drain in-flight writers. Wait for all currently executing
    // event-writing functions to complete before tearing down.
    // Uses ReadAcquire for ARM64 correctness and enforces a maximum
    // drain timeout to prevent indefinite system hang on driver unload.
    //
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&drainStartTime);
    delay.QuadPart = -(LONGLONG)(ETW_SHUTDOWN_DRAIN_SLEEP_MS * 10000);
    spinCount = 0;

    while (ReadAcquire(&g_EtwGlobals.InFlightWriters) > 0) {
        LONG64 now;
        KeQuerySystemTimePrecise((PLARGE_INTEGER)&now);
        if ((now - drainStartTime) > ETW_SHUTDOWN_MAX_DRAIN_100NS) {
            //
            // Drain timeout exceeded. Proceed with teardown.
            // EtwUnregister will internally synchronize with any
            // in-progress EtwWrite calls.
            //
            break;
        }

        spinCount++;
        if (spinCount > ETW_SHUTDOWN_DRAIN_SPIN_LIMIT) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            spinCount = 0;
        }
        KeMemoryBarrier();
    }

    //
    // All writers have drained. Unregister from ETW.
    //
    if (g_EtwGlobals.ProviderHandle != 0) {
        EtwUnregister(g_EtwGlobals.ProviderHandle);
        g_EtwGlobals.ProviderHandle = 0;
    }

    //
    // Cleanup lookaside list
    //
    ExDeleteNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside);

    //
    // Final state transition
    //
    InterlockedExchange(&g_EtwGlobals.State, EtwState_Shutdown);
}


_Use_decl_annotations_
BOOLEAN
EtwProviderIsEnabled(
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords
    )
/*++

Routine Description:

    Checks if the ETW provider is enabled for the specified level and keywords.
    Uses atomic reads of the enable state to avoid tearing from concurrent
    enable callback updates.

--*/
{
    LONG enabled;
    UCHAR enableLevel;
    LONGLONG enableFlags;

    //
    // Fast check: is the provider in READY state and enabled?
    // Use ReadAcquire to enforce ordering on ARM64: subsequent reads
    // of Enabled/EnableLevel/EnableFlags must not be reordered before
    // this state check.
    //
    if (ReadAcquire(&g_EtwGlobals.State) != EtwState_Ready) {
        return FALSE;
    }

    enabled = InterlockedOr(&g_EtwGlobals.Enabled, 0);
    if (!enabled) {
        return FALSE;
    }

    if (g_EtwGlobals.ProviderHandle == 0) {
        return FALSE;
    }

    //
    // Atomic snapshot of enable level and flags.
    // These are written by InterlockedExchange in the enable callback.
    //
    enableLevel = *((volatile UCHAR*)&g_EtwGlobals.EnableLevel);
    MemoryBarrier();
    enableFlags = InterlockedOr64((volatile LONG64*)&g_EtwGlobals.EnableFlags, 0);

    if (Level > enableLevel) {
        return FALSE;
    }

    if ((Keywords & (ULONGLONG)enableFlags) == 0) {
        return FALSE;
    }

    return TRUE;
}


// ============================================================================
// In-Flight Writer Reference Counting
// ============================================================================

static BOOLEAN
EtwpAcquireWriterRef(
    VOID
    )
/*++

Routine Description:

    Acquires a writer reference. Returns FALSE if the provider is not
    in READY state (preventing new writes during shutdown).

    Uses ReadAcquire for both state checks to enforce correct ordering
    on weakly-ordered architectures (ARM64). The re-check after
    InterlockedIncrement ensures that if shutdown raced in, we release
    the reference before the shutdown drain loop completes.

--*/
{
    if (ReadAcquire(&g_EtwGlobals.State) != EtwState_Ready) {
        return FALSE;
    }

    InterlockedIncrement(&g_EtwGlobals.InFlightWriters);

    //
    // Double-check after incrementing with acquire semantics.
    // On ARM64, without ReadAcquire the CPU could reorder this load
    // before the InterlockedIncrement, breaking the shutdown drain
    // invariant and causing use-after-free of the lookaside list.
    //
    if (ReadAcquire(&g_EtwGlobals.State) != EtwState_Ready) {
        InterlockedDecrement(&g_EtwGlobals.InFlightWriters);
        return FALSE;
    }

    return TRUE;
}


static VOID
EtwpReleaseWriterRef(
    VOID
    )
{
    InterlockedDecrement(&g_EtwGlobals.InFlightWriters);
}


// ============================================================================
// Bounded String Copy Helpers
// ============================================================================

_Use_decl_annotations_
static VOID
EtwpCopyBoundedString(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCWSTR Src,
    _In_ ULONG MaxSrcChars
    )
/*++

Routine Description:

    Copies a PCWSTR to a fixed-size WCHAR buffer with bounded length scan.
    Uses wcsnlen to prevent scanning past MaxSrcChars characters.
    Always null-terminates the destination.

    TRUSTED-CALLER CONTRACT: Src must point to valid, readable kernel memory
    of at least MaxSrcChars * sizeof(WCHAR) bytes. This function is internal
    to the ETW provider and must NOT be called with user-mode pointers or
    pointers to freed/paged-out memory at elevated IRQL.

--*/
{
    size_t srcLen;
    ULONG copyChars;

    if (DestChars == 0) {
        return;
    }

    srcLen = wcsnlen(Src, MaxSrcChars);
    copyChars = (ULONG)min(srcLen, (size_t)(DestChars - 1));

    if (copyChars > 0) {
        RtlCopyMemory(Dest, Src, copyChars * sizeof(WCHAR));
    }

    Dest[copyChars] = L'\0';
}


_Use_decl_annotations_
static VOID
EtwpCopyUnicodeStringBounded(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCUNICODE_STRING Src
    )
/*++

Routine Description:

    Copies a UNICODE_STRING to a fixed-size WCHAR buffer.
    Uses the Length field (in bytes) — no unbounded string scan.
    Always null-terminates the destination.

--*/
{
    ULONG srcChars;
    ULONG copyChars;

    if (DestChars == 0) {
        return;
    }

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        Dest[0] = L'\0';
        return;
    }

    srcChars = Src->Length / sizeof(WCHAR);
    copyChars = min(srcChars, DestChars - 1);

    if (copyChars > 0) {
        RtlCopyMemory(Dest, Src->Buffer, copyChars * sizeof(WCHAR));
    }

    Dest[copyChars] = L'\0';
}


// ============================================================================
// Event Writing - Process Events
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteProcessEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags,
    _In_ UINT32 ExitCode
    )
{
    NTSTATUS status;
    PETW_PROCESS_EVENT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    //
    // Select event descriptor based on event ID
    //
    switch (EventId) {
        case EtwEventId_ProcessCreate:
            descriptor = &EtwDescriptor_ProcessCreate;
            break;
        case EtwEventId_ProcessTerminate:
            descriptor = &EtwDescriptor_ProcessTerminate;
            break;
        case EtwEventId_ProcessSuspicious:
            descriptor = &EtwDescriptor_ProcessSuspicious;
            break;
        case EtwEventId_ProcessBlocked:
            descriptor = &EtwDescriptor_ProcessBlocked;
            break;
        default:
            EtwpReleaseWriterRef();
            return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if this event type is enabled
    //
    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    //
    // Per-severity rate limit check (CRITICAL events bypass)
    //
    if (!EtwpCheckRateLimit(descriptor->Level)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate event buffer from lookaside (correctly sized)
    //
    event = (PETW_PROCESS_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_PROCESS_EVENT));

    //
    // Fill common header (includes SessionId from PsGetCurrentProcessSessionId)
    //
    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->ParentProcessId = ParentProcessId;
    event->Flags = Flags;
    event->ThreatScore = ThreatScore;
    event->ExitCode = ExitCode;

    //
    // Copy strings using length-counted UNICODE_STRING — no unbounded scan
    //
    if (ImagePath != NULL) {
        EtwpCopyUnicodeStringBounded(
            event->ImagePath,
            ETW_MAX_PATH_CHARS,
            ImagePath
            );
    }

    if (CommandLine != NULL) {
        EtwpCopyUnicodeStringBounded(
            event->CommandLine,
            ETW_MAX_CMDLINE_CHARS,
            CommandLine
            );
    }

    //
    // Write the event
    //
    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_PROCESS_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_PROCESS_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    EtwpReleaseWriterRef();

    return status;
}


// ============================================================================
// Event Writing - File Events
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteFileEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_opt_ PCUNICODE_STRING FilePath,
    _In_ UINT32 Operation,
    _In_ UINT64 FileSize,
    _In_ UINT32 Verdict,
    _In_opt_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore
    )
{
    NTSTATUS status;
    PETW_FILE_EVENT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    //
    // Select event descriptor
    //
    switch (EventId) {
        case EtwEventId_FileCreate:
            descriptor = &EtwDescriptor_FileCreate;
            break;
        case EtwEventId_FileWrite:
            descriptor = &EtwDescriptor_FileWrite;
            break;
        case EtwEventId_FileScanResult:
            descriptor = &EtwDescriptor_FileScanResult;
            break;
        case EtwEventId_FileBlocked:
            descriptor = &EtwDescriptor_FileBlocked;
            break;
        case EtwEventId_FileQuarantined:
            descriptor = &EtwDescriptor_FileQuarantined;
            break;
        default:
            EtwpReleaseWriterRef();
            return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit(descriptor->Level)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    event = (PETW_FILE_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_FILE_EVENT));

    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->Operation = Operation;
    event->Disposition = 0;
    event->FileSize = FileSize;
    event->Verdict = Verdict;
    event->ThreatScore = ThreatScore;

    //
    // Copy file path using UNICODE_STRING (length-counted, safe)
    //
    if (FilePath != NULL) {
        EtwpCopyUnicodeStringBounded(
            event->FilePath,
            ETW_MAX_PATH_CHARS,
            FilePath
            );
    }

    //
    // Copy threat name using bounded wcsnlen
    //
    if (ThreatName != NULL) {
        EtwpCopyBoundedString(
            event->ThreatName,
            ETW_MAX_THREAT_NAME_CHARS,
            ThreatName,
            ETW_MAX_THREAT_NAME_CHARS
            );
    }

    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_FILE_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_FILE_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    EtwpReleaseWriterRef();

    return status;
}


// ============================================================================
// Event Writing - Network Events
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteNetworkEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ const ETW_NETWORK_EVENT* Event
    )
/*++

Routine Description:

    Writes a network-related ETW event. Makes an internal copy of the
    caller's event structure to avoid mutating the caller's buffer and
    to ensure the data resides in NonPaged pool.

    TRUSTED-CALLER CONTRACT: Event must point to a fully-initialized
    ETW_NETWORK_EVENT structure of sizeof(ETW_NETWORK_EVENT) bytes in
    valid, readable kernel memory. This function performs a flat copy
    of the entire structure.

--*/
{
    NTSTATUS status;
    PETW_NETWORK_EVENT localEvent = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (Event == NULL) {
        EtwpReleaseWriterRef();
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Select event descriptor — each event ID maps to its own descriptor
    // so ETW consumers see the correct Id in the trace.
    //
    switch (EventId) {
        case EtwEventId_NetworkConnect:
            descriptor = &EtwDescriptor_NetworkConnect;
            break;
        case EtwEventId_NetworkListen:
            descriptor = &EtwDescriptor_NetworkListen;
            break;
        case EtwEventId_DnsQuery:
            descriptor = &EtwDescriptor_DnsQuery;
            break;
        case EtwEventId_NetworkBlocked:
            descriptor = &EtwDescriptor_NetworkBlocked;
            break;
        case EtwEventId_ExfiltrationDetected:
            descriptor = &EtwDescriptor_ExfiltrationDetected;
            break;
        case EtwEventId_C2Detected:
            descriptor = &EtwDescriptor_C2Detected;
            break;
        default:
            EtwpReleaseWriterRef();
            return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit(descriptor->Level)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate our own copy from the lookaside list.
    // This prevents mutation of the caller's buffer and ensures
    // the event data is in NonPaged pool.
    //
    localEvent = (PETW_NETWORK_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (localEvent == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(localEvent, Event, sizeof(ETW_NETWORK_EVENT));

    //
    // Always fill the common header on our copy
    //
    EtwpFillCommonHeader(&localEvent->Common, Event->Common.ProcessId);

    EventDataDescCreate(&dataDescriptor, localEvent, sizeof(ETW_NETWORK_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_NETWORK_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, localEvent);

    EtwpReleaseWriterRef();

    return status;
}


// ============================================================================
// Event Writing - Behavioral Events
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteBehaviorEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 BehaviorType,
    _In_ UINT32 Category,
    _In_ UINT64 ChainId,
    _In_ UINT32 MitreTechnique,
    _In_ UINT32 MitreTactic,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Confidence,
    _In_opt_ PCWSTR Description
    )
{
    NTSTATUS status;
    PETW_BEHAVIOR_EVENT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    //
    // Select event descriptor — each event ID maps to its own descriptor
    // so ETW consumers see the correct Id in the trace.
    //
    switch (EventId) {
        case EtwEventId_BehaviorAlert:
            descriptor = &EtwDescriptor_BehaviorAlert;
            break;
        case EtwEventId_AttackChainStarted:
            descriptor = &EtwDescriptor_AttackChainStarted;
            break;
        case EtwEventId_AttackChainUpdated:
            descriptor = &EtwDescriptor_AttackChainUpdated;
            break;
        case EtwEventId_AttackChainCompleted:
            descriptor = &EtwDescriptor_AttackChainCompleted;
            break;
        case EtwEventId_MitreDetection:
            descriptor = &EtwDescriptor_MitreDetection;
            break;
        default:
            EtwpReleaseWriterRef();
            return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit(descriptor->Level)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    event = (PETW_BEHAVIOR_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_BEHAVIOR_EVENT));

    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->BehaviorType = BehaviorType;
    event->Category = Category;
    event->ThreatScore = ThreatScore;
    event->Confidence = Confidence;
    event->ChainId = ChainId;
    event->MitreTechnique = MitreTechnique;
    event->MitreTactic = MitreTactic;

    //
    // Copy description using bounded wcsnlen
    //
    if (Description != NULL) {
        EtwpCopyBoundedString(
            event->Description,
            ETW_MAX_DESCRIPTION_CHARS,
            Description,
            ETW_MAX_DESCRIPTION_CHARS
            );
    }

    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_BEHAVIOR_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_BEHAVIOR_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    EtwpReleaseWriterRef();

    return status;
}


// ============================================================================
// Event Writing - Security Alerts
// ============================================================================

_Use_decl_annotations_
static PCEVENT_DESCRIPTOR
EtwpGetSecurityDescriptor(
    _In_ UINT32 AlertType
    )
/*++

Routine Description:

    Maps security alert type to event descriptor.
    Returns NULL for unrecognized types.

--*/
{
    switch (AlertType) {
        case EtwEventId_TamperAttempt:
            return &EtwDescriptor_TamperAttempt;
        case EtwEventId_EvasionAttempt:
            return &EtwDescriptor_EvasionAttempt;
        case EtwEventId_DirectSyscall:
            return &EtwDescriptor_DirectSyscall;
        case EtwEventId_PrivilegeEscalation:
            return &EtwDescriptor_PrivilegeEscalation;
        case EtwEventId_CredentialAccess:
            return &EtwDescriptor_CredentialAccess;
        default:
            return NULL;
    }
}


_Use_decl_annotations_
NTSTATUS
EtwWriteSecurityAlert(
    _In_ UINT32 AlertType,
    _In_ UINT32 Severity,
    _In_ UINT32 ProcessId,
    _In_ UINT64 ChainId,
    _In_ PCWSTR Title,
    _In_ PCWSTR Description,
    _In_opt_ PCWSTR ProcessPath,
    _In_opt_ PCWSTR TargetPath,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 ResponseAction
    )
{
    NTSTATUS status;
    PETW_SECURITY_ALERT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (Title == NULL || Description == NULL) {
        EtwpReleaseWriterRef();
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Map alert type to descriptor. Return INVALID_PARAMETER for unknown types
    // instead of silently defaulting to TamperAttempt (prevents false positives).
    //
    descriptor = EtwpGetSecurityDescriptor(AlertType);
    if (descriptor == NULL) {
        EtwpReleaseWriterRef();
        return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    //
    // Security alerts at CRITICAL level bypass rate limiting.
    //
    if (!EtwpCheckRateLimit(descriptor->Level)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    event = (PETW_SECURITY_ALERT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_SECURITY_ALERT));

    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->AlertType = AlertType;
    event->Severity = Severity;
    event->ThreatScore = ThreatScore;
    event->ResponseAction = ResponseAction;
    event->ChainId = ChainId;

    //
    // All string copies bounded by wcsnlen via EtwpCopyBoundedString
    //
    EtwpCopyBoundedString(
        event->AlertTitle,
        ETW_MAX_ALERT_TITLE_CHARS,
        Title,
        ETW_MAX_ALERT_TITLE_CHARS
        );

    EtwpCopyBoundedString(
        event->AlertDescription,
        ETW_MAX_ALERT_DESC_CHARS,
        Description,
        ETW_MAX_ALERT_DESC_CHARS
        );

    if (ProcessPath != NULL) {
        EtwpCopyBoundedString(
            event->ProcessPath,
            ETW_MAX_PATH_CHARS,
            ProcessPath,
            ETW_MAX_PATH_CHARS
            );
    }

    if (TargetPath != NULL) {
        EtwpCopyBoundedString(
            event->TargetPath,
            ETW_MAX_PATH_CHARS,
            TargetPath,
            ETW_MAX_PATH_CHARS
            );
    }

    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_SECURITY_ALERT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_SECURITY_ALERT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    EtwpReleaseWriterRef();

    return status;
}


// ============================================================================
// Event Writing - Diagnostic Events
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteDiagnosticEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UCHAR Level,
    _In_ UINT32 ComponentId,
    _In_ PCWSTR Message,
    _In_ UINT32 ErrorCode
    )
{
    NTSTATUS status;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptors[4];
    UINT64 timestamp;
    size_t messageLen;
    ULONG messageSizeBytes;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (Message == NULL) {
        EtwpReleaseWriterRef();
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Select descriptor based on event ID
    //
    switch (EventId) {
        case EtwEventId_DriverStarted:
            descriptor = &EtwDescriptor_DriverStarted;
            break;
        case EtwEventId_DriverStopping:
            descriptor = &EtwDescriptor_DriverStopping;
            break;
        case EtwEventId_Heartbeat:
            descriptor = &EtwDescriptor_Heartbeat;
            break;
        case EtwEventId_ComponentHealth:
            descriptor = &EtwDescriptor_ComponentHealth;
            break;
        case EtwEventId_Error:
        default:
            descriptor = &EtwDescriptor_Error;
            break;
    }

    if (!EtwProviderIsEnabled(Level, ETW_KEYWORD_DIAGNOSTIC)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    //
    // Diagnostic events ARE rate-limited (fixes MEDIUM-1)
    //
    if (!EtwpCheckRateLimit(descriptor->Level)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Build event data with bounded message length
    //
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&timestamp);

    //
    // Bound the message scan to prevent runaway wcslen.
    // Only include the null terminator byte if wcsnlen actually found one
    // within the limit. If the string is exactly ETW_MAX_DIAGNOSTIC_MESSAGE_CHARS
    // long with no null, we must not read past the end of the buffer.
    //
    messageLen = wcsnlen(Message, ETW_MAX_DIAGNOSTIC_MESSAGE_CHARS);
    if (messageLen < ETW_MAX_DIAGNOSTIC_MESSAGE_CHARS) {
        messageSizeBytes = (ULONG)((messageLen + 1) * sizeof(WCHAR));
    } else {
        messageSizeBytes = (ULONG)(messageLen * sizeof(WCHAR));
    }

    EventDataDescCreate(&dataDescriptors[0], &timestamp, sizeof(UINT64));
    EventDataDescCreate(&dataDescriptors[1], &ComponentId, sizeof(UINT32));
    EventDataDescCreate(&dataDescriptors[2], &ErrorCode, sizeof(UINT32));
    EventDataDescCreate(&dataDescriptors[3], Message, messageSizeBytes);

    status = EtwpWriteEvent(descriptor, 4, dataDescriptors);

    EtwpUpdateStatistics(
        sizeof(UINT64) + sizeof(UINT32) * 2 + messageSizeBytes,
        NT_SUCCESS(status)
        );

    EtwpReleaseWriterRef();

    return status;
}


_Use_decl_annotations_
NTSTATUS
EtwWritePerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    )
{
    NTSTATUS status;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!EtwpAcquireWriterRef()) {
        return STATUS_SUCCESS;
    }

    if (!g_EtwGlobals.Enabled) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (Stats == NULL) {
        EtwpReleaseWriterRef();
        return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_TELEMETRY)) {
        EtwpReleaseWriterRef();
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit(ETW_LEVEL_INFORMATIONAL)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        EtwpReleaseWriterRef();
        return STATUS_QUOTA_EXCEEDED;
    }

    EventDataDescCreate(&dataDescriptor, Stats, sizeof(TELEMETRY_PERFORMANCE));

    status = EtwpWriteEvent(&EtwDescriptor_PerformanceStats, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(TELEMETRY_PERFORMANCE), NT_SUCCESS(status));

    EtwpReleaseWriterRef();

    return status;
}


// ============================================================================
// Statistics
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwProviderGetStatistics(
    _Out_ PUINT64 EventsWritten,
    _Out_ PUINT64 EventsDropped,
    _Out_ PUINT64 BytesWritten
    )
{
    if (EventsWritten == NULL || EventsDropped == NULL || BytesWritten == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic reads: use InterlockedOr64 to ensure 64-bit atomicity
    // on both 32-bit and 64-bit platforms.
    //
    *EventsWritten = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_EtwGlobals.EventsWritten, 0
        );
    *EventsDropped = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_EtwGlobals.EventsDropped, 0
        );
    *BytesWritten = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_EtwGlobals.BytesWritten, 0
        );

    return STATUS_SUCCESS;
}


// ============================================================================
// Internal Functions
// ============================================================================

static
_Use_decl_annotations_
BOOLEAN
EtwpCheckRateLimit(
    _In_ UCHAR EventLevel
    )
/*++

Routine Description:

    Checks if we're within the rate limit for event writing.
    Resets counter each second using atomic operations to prevent torn
    reads/writes on 32-bit platforms.

    CRITICAL-level events (level <= ETW_LEVEL_CRITICAL) ALWAYS pass
    the rate limit check. Security-critical events must never be dropped
    in favor of verbose telemetry.

Return Value:

    TRUE if under rate limit or event is CRITICAL, FALSE if limit exceeded.

--*/
{
    LONG64 currentTime;
    LONG64 windowStart;
    LONG64 elapsed;
    LONG currentCount;

    //
    // CRITICAL events bypass rate limiting entirely.
    // Tamper attempts, C2 detections, privilege escalation — these must
    // always be emitted regardless of event volume from other sources.
    //
    if (EventLevel <= ETW_LEVEL_CRITICAL) {
        return TRUE;
    }

    KeQuerySystemTimePrecise((PLARGE_INTEGER)&currentTime);

    //
    // Atomic read of the window start time
    //
    windowStart = InterlockedOr64(&g_EtwGlobals.CurrentSecondStart, 0);

    elapsed = currentTime - windowStart;

    if (elapsed >= ETW_RATE_LIMIT_WINDOW_100NS) {
        //
        // Attempt to reset the window atomically.
        // Only one thread wins the CAS; others fall through to increment.
        //
        if (InterlockedCompareExchange64(
                &g_EtwGlobals.CurrentSecondStart,
                currentTime,
                windowStart
                ) == windowStart) {
            //
            // We won the race — reset the counter.
            //
            InterlockedExchange(&g_EtwGlobals.EventsThisSecond, 1);
            return TRUE;
        }
        //
        // Another thread reset the window. Fall through to normal increment.
        //
    }

    //
    // Increment and check against limit
    //
    currentCount = InterlockedIncrement(&g_EtwGlobals.EventsThisSecond);

    return (currentCount <= (LONG)g_EtwGlobals.MaxEventsPerSecond);
}


static
_Use_decl_annotations_
VOID
EtwpUpdateStatistics(
    _In_ ULONG EventSize,
    _In_ BOOLEAN Success
    )
{
    if (Success) {
        InterlockedIncrement64(&g_EtwGlobals.EventsWritten);
        InterlockedAdd64(&g_EtwGlobals.BytesWritten, (LONG64)EventSize);
    } else {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
    }
}


static
_Use_decl_annotations_
VOID
EtwpFillCommonHeader(
    _Out_ PETW_EVENT_COMMON Common,
    _In_ UINT32 ProcessId
    )
{
    LARGE_INTEGER timestamp;
    ULONG sessionId = 0;

    KeQuerySystemTimePrecise(&timestamp);

    Common->Timestamp = (UINT64)timestamp.QuadPart;
    Common->ProcessId = ProcessId;
    Common->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

    //
    // Populate session ID via MmGetSessionId. Safe at IRQL <= DISPATCH_LEVEL.
    //
    sessionId = MmGetSessionId(PsGetCurrentProcess());
    Common->SessionId = sessionId;
    Common->Reserved = 0;
}


static
_Use_decl_annotations_
NTSTATUS
EtwpWriteEvent(
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    )
{
    NTSTATUS status;

    if (g_EtwGlobals.ProviderHandle == 0) {
        return STATUS_INVALID_HANDLE;
    }

    status = EtwWrite(
        g_EtwGlobals.ProviderHandle,
        EventDescriptor,
        NULL,       // ActivityId
        UserDataCount,
        UserData
        );

    return status;
}


static
_Use_decl_annotations_
VOID NTAPI
EtwpEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    )
/*++

Routine Description:

    Callback invoked when an ETW session enables/disables the provider.
    Updates enable state using interlocked operations for each field
    to prevent tearing when read by EtwProviderIsEnabled.

    Does NOT track consumer count manually. ETW does not guarantee
    paired enable/disable calls (sessions can crash, be torn down, or
    send redundant disables), so manual refcounting drifts over time.
    Instead, we simply set Enabled on ENABLE and clear on DISABLE.

    CAPTURE_STATE is acknowledged but does NOT call EtwWrite from
    within this callback to avoid potential deadlock with ETW's
    internal locks when concurrent sessions are being enabled.

--*/
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    if (IsEnabled == EVENT_CONTROL_CODE_ENABLE_PROVIDER) {
        //
        // Provider is being enabled.
        // Write enable state atomically per field. Order matters:
        // set Level and Flags before setting Enabled, so that
        // concurrent readers see consistent filter state.
        //
        InterlockedExchange8((CHAR volatile*)&g_EtwGlobals.EnableLevel, (CHAR)Level);
        MemoryBarrier();
        InterlockedExchange64(&g_EtwGlobals.EnableFlags, (LONG64)MatchAnyKeyword);
        MemoryBarrier();
        InterlockedExchange(&g_EtwGlobals.Enabled, TRUE);

    } else if (IsEnabled == EVENT_CONTROL_CODE_DISABLE_PROVIDER) {
        //
        // Provider is being disabled.
        // Unconditionally disable. We do not track consumer count because
        // ETW does not guarantee paired enable/disable callbacks.
        //
        InterlockedExchange(&g_EtwGlobals.Enabled, FALSE);
        MemoryBarrier();
        InterlockedExchange8((CHAR volatile*)&g_EtwGlobals.EnableLevel, 0);
        InterlockedExchange64(&g_EtwGlobals.EnableFlags, 0);

    } else if (IsEnabled == EVENT_CONTROL_CODE_CAPTURE_STATE) {
        //
        // Consumer requesting state capture.
        // We intentionally do NOT emit an ETW event from within this
        // callback. Calling EtwWrite here risks deadlock with ETW's
        // internal session locks when multiple sessions are being
        // enabled/disabled concurrently. The state is already visible
        // to consumers via the normal event stream.
        //
        NOTHING;
    }
}
