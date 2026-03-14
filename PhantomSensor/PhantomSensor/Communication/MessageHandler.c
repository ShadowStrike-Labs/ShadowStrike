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
 * ShadowStrike NGAV - MESSAGE HANDLER IMPLEMENTATION
 * ============================================================================
 *
 * @file MessageHandler.c
 * @brief Enterprise-grade message dispatching and routing logic.
 *
 * This module handles all incoming messages from user-mode and routes them
 * to the appropriate subsystem handlers. It provides:
 *
 * - Message validation (magic, version, size bounds) with SEH protection
 * - User-mode buffer probing (ProbeForRead/ProbeForWrite)
 * - Authorization checks for privileged operations
 * - Safe callback invocation (copy pointer, release lock, then call)
 * - Subsystem registration and callback dispatch
 * - Configuration updates with validation
 * - Policy management
 * - Protected process registration
 * - Statistics and status queries
 * - Scan verdict processing
 *
 * Thread Safety:
 * - Handler registration protected by EX_PUSH_LOCK
 * - Configuration updates protected by driver config lock
 * - Statistics use interlocked operations
 * - Callbacks invoked outside of locks to prevent deadlock
 * - Active invocation counting for safe unregistration
 *
 * IRQL:
 * - Message processing: PASSIVE_LEVEL (may touch paged memory)
 * - Handler registration: PASSIVE_LEVEL
 * - Protected process queries: APC_LEVEL max (uses push locks)
 *
 * Security:
 * - All user-mode buffers probed and accessed under SEH
 * - Authorization required for privileged operations
 * - Input validation on all parameters
 * - ProcessName fields always null-terminated
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MessageHandler.h"
#include "MessageQueue.h"
#include "../../Shared/MessageTypes.h"
#include "../../Shared/MessageProtocol.h"
#include "../../Shared/ErrorCodes.h"
#include "../Core/Globals.h"
#include "../Core/DriverEntry.h"

// Detection module headers for data push handlers
#include <ntstrsafe.h>
#include "../Behavioral/IOCMatcher.h"
#include "../Behavioral/RuleEngine.h"
#include "../Behavioral/BehaviorEngine.h"
#include "../../Shared/BehaviorTypes.h"
#include "../Network/C2Detection.h"
#include "../Network/DnsMonitor.h"
#include "../Network/NetworkReputation.h"
#include "../Network/NetworkFilter.h"
#include "../Network/SSLInspection.h"
#include "../Exclusions/ExclusionManager.h"
#include "../Callbacks/Object/ObjectCallback.h"
#include "../Callbacks/Object/ProcessProtection.h"
#include "Compression.h"
#include "ScanBridge.h"
#include "TelemetryBuffer.h"
#include "../Context/InstanceContext.h"
#include "../ETW/ETWProvider.h"
#include "../ETW/EventSchema.h"
#include "../ETW/ManifestGenerator.h"
#include "../ETW/TelemetryEvents.h"
#include "../Memory/MemoryMonitor.h"
#include "../Memory/MemoryScanner.h"
#include "../Memory/HollowingDetector.h"

// ============================================================================
// CONSTANTS
// ============================================================================

#define MH_TAG                          'hMsS'
#define MH_KERNEL_BUFFER_TAG            'bMsS'

//
// Maximum size we will copy from user-mode to kernel buffer
// Prevents excessive kernel memory consumption from malicious input
//
#define MH_MAX_INPUT_BUFFER_SIZE        (64 * 1024)

//
// Maximum size for local kernel output buffer.
// Handlers write into this, then it's copied to user-mode under SEH.
// Must accommodate the largest response struct (SHADOWSTRIKE_DRIVER_STATUS).
//
#define MH_MAX_LOCAL_OUTPUT_SIZE        1024

// ============================================================================
// COMPILE-TIME VALIDATIONS
// ============================================================================

C_ASSERT(MH_MAX_HANDLERS >= FilterMessageType_Max);
C_ASSERT(MH_MAX_PROTECTED_PROCESSES > 0);
C_ASSERT(MH_MAX_PROTECTED_PROCESSES <= 1024);
C_ASSERT(sizeof(SHADOWSTRIKE_DRIVER_STATUS) <= MH_MAX_LOCAL_OUTPUT_SIZE);
C_ASSERT(sizeof(SHADOWSTRIKE_GENERIC_REPLY) <= MH_MAX_LOCAL_OUTPUT_SIZE);

// ============================================================================
// TYPES
// ============================================================================

/**
 * @brief Registered message handler entry.
 *
 * Contains callback pointer, context, statistics, and active invocation count.
 * The ActiveInvocations field is used for safe unregistration.
 */
typedef struct _MH_HANDLER_ENTRY {
    BOOLEAN Registered;
    UINT8 Reserved1[3];
    SHADOWSTRIKE_MESSAGE_TYPE MessageType;
    PMH_MESSAGE_HANDLER_CALLBACK Callback;
    PVOID Context;
    volatile LONG64 InvocationCount;
    volatile LONG64 ErrorCount;
    volatile LONG ActiveInvocations;  // For safe unregistration
} MH_HANDLER_ENTRY, *PMH_HANDLER_ENTRY;

/**
 * @brief Protected process entry.
 */
typedef struct _MH_PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    UINT32 ProcessId;
    UINT32 ProtectionFlags;
    LARGE_INTEGER RegistrationTime;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
} MH_PROTECTED_PROCESS, *PMH_PROTECTED_PROCESS;

C_ASSERT(sizeof(MH_PROTECTED_PROCESS) <= 1024);

/**
 * @brief Message handler global state.
 */
typedef struct _MH_GLOBALS {
    //
    // Initialization state - use interlocked operations
    //
    volatile LONG InitState;  // 0=uninit, 1=initializing, 2=initialized
    UINT8 Reserved[4];

    //
    // Handler table
    //
    MH_HANDLER_ENTRY Handlers[MH_MAX_HANDLERS];
    EX_PUSH_LOCK HandlersLock;

    //
    // Protected processes
    //
    LIST_ENTRY ProtectedProcessList;
    EX_PUSH_LOCK ProtectedProcessLock;
    volatile LONG ProtectedProcessCount;
    NPAGED_LOOKASIDE_LIST ProtectedProcessLookaside;
    BOOLEAN LookasideInitialized;
    UINT8 Reserved2[7];

    //
    // Statistics
    //
    volatile LONG64 TotalMessagesProcessed;
    volatile LONG64 TotalMessagesSucceeded;
    volatile LONG64 TotalMessagesFailed;
    volatile LONG64 TotalInvalidMessages;
    volatile LONG64 TotalUnhandledMessages;
    volatile LONG64 TotalUnauthorizedAttempts;
} MH_GLOBALS, *PMH_GLOBALS;

//
// Initialization states
//
#define MH_STATE_UNINITIALIZED      0
#define MH_STATE_INITIALIZING       1
#define MH_STATE_INITIALIZED        2

// ============================================================================
// GLOBALS
// ============================================================================

static MH_GLOBALS g_MhGlobals = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
MhpValidateAndCopyMessage(
    _In_reads_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PVOID* KernelBuffer,
    _Out_ PULONG KernelBufferSize,
    _Out_ PSS_MESSAGE_HEADER* Header,
    _Out_ PVOID* Payload,
    _Out_ PULONG PayloadSize
    );

static VOID
MhpFreeKernelBuffer(
    _In_ PVOID KernelBuffer
    );

static NTSTATUS
MhpCopyOutputToUser(
    _Out_writes_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

static BOOLEAN
MhpIsPrivilegedOperation(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    );

static NTSTATUS
MhpHandleHeartbeat(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleConfigUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePolicyUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleDriverStatusQuery(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleProtectedProcessRegister(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleScanVerdict(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleEnableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleDisableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

// Data push handlers (user-mode → kernel threat intel)
static NTSTATUS
MhpHandlePushHashDatabase(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePushPatternDatabase(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePushSignatureDatabase(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePushIoCFeed(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePushWhitelist(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleUpdateBehavioralRules(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePushNetworkIoC(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleExclusionUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, MhInitialize)
#pragma alloc_text(PAGE, MhShutdown)
#pragma alloc_text(PAGE, MhRegisterHandler)
#pragma alloc_text(PAGE, MhUnregisterHandler)
#pragma alloc_text(PAGE, ShadowStrikeProcessUserMessage)
#pragma alloc_text(PAGE, MhIsCallerAuthorized)
#pragma alloc_text(PAGE, MhpValidateAndCopyMessage)
#pragma alloc_text(PAGE, MhpCopyOutputToUser)
#pragma alloc_text(PAGE, MhpHandleHeartbeat)
#pragma alloc_text(PAGE, MhpHandleConfigUpdate)
#pragma alloc_text(PAGE, MhpHandlePolicyUpdate)
#pragma alloc_text(PAGE, MhpHandleDriverStatusQuery)
#pragma alloc_text(PAGE, MhpHandleProtectedProcessRegister)
#pragma alloc_text(PAGE, MhpHandleScanVerdict)
#pragma alloc_text(PAGE, MhpHandleEnableFiltering)
#pragma alloc_text(PAGE, MhpHandleDisableFiltering)
#pragma alloc_text(PAGE, MhpHandlePushHashDatabase)
#pragma alloc_text(PAGE, MhpHandlePushPatternDatabase)
#pragma alloc_text(PAGE, MhpHandlePushSignatureDatabase)
#pragma alloc_text(PAGE, MhpHandlePushIoCFeed)
#pragma alloc_text(PAGE, MhpHandlePushWhitelist)
#pragma alloc_text(PAGE, MhpHandleUpdateBehavioralRules)
#pragma alloc_text(PAGE, MhpHandlePushNetworkIoC)
#pragma alloc_text(PAGE, MhpHandleExclusionUpdate)
#endif

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message handler subsystem.
 *
 * Uses interlocked operations to prevent race conditions during initialization.
 *
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhInitialize(
    VOID
    )
{
    NTSTATUS status;
    LONG prevState;

    PAGED_CODE();

    //
    // Atomically transition from UNINITIALIZED to INITIALIZING
    // This prevents double-initialization race conditions
    //
    prevState = InterlockedCompareExchange(
        &g_MhGlobals.InitState,
        MH_STATE_INITIALIZING,
        MH_STATE_UNINITIALIZED
    );

    if (prevState == MH_STATE_INITIALIZED) {
        return STATUS_ALREADY_REGISTERED;
    }

    if (prevState == MH_STATE_INITIALIZING) {
        //
        // Another thread is initializing - this is a logic error
        //
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // We won the race - initialize everything
    // Note: Do NOT zero the structure here as InitState is already set
    //

    //
    // Initialize handler table
    //
    RtlZeroMemory(g_MhGlobals.Handlers, sizeof(g_MhGlobals.Handlers));
    ExInitializePushLock(&g_MhGlobals.HandlersLock);

    //
    // Initialize protected process list
    //
    InitializeListHead(&g_MhGlobals.ProtectedProcessList);
    ExInitializePushLock(&g_MhGlobals.ProtectedProcessLock);
    g_MhGlobals.ProtectedProcessCount = 0;

    ExInitializeNPagedLookasideList(
        &g_MhGlobals.ProtectedProcessLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MH_PROTECTED_PROCESS),
        MH_TAG,
        0
    );
    g_MhGlobals.LookasideInitialized = TRUE;

    //
    // Initialize statistics
    //
    g_MhGlobals.TotalMessagesProcessed = 0;
    g_MhGlobals.TotalMessagesSucceeded = 0;
    g_MhGlobals.TotalMessagesFailed = 0;
    g_MhGlobals.TotalInvalidMessages = 0;
    g_MhGlobals.TotalUnhandledMessages = 0;
    g_MhGlobals.TotalUnauthorizedAttempts = 0;

    //
    // Register built-in handlers - check each return value
    //
    status = MhRegisterHandler(FilterMessageType_Heartbeat, MhpHandleHeartbeat, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_ConfigUpdate, MhpHandleConfigUpdate, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_UpdatePolicy, MhpHandlePolicyUpdate, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_QueryDriverStatus, MhpHandleDriverStatusQuery, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_RegisterProtectedProcess, MhpHandleProtectedProcessRegister, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_ScanVerdict, MhpHandleScanVerdict, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_EnableFiltering, MhpHandleEnableFiltering, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_DisableFiltering, MhpHandleDisableFiltering, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    //
    // Register data push handlers (user-mode → kernel threat intel)
    //
    status = MhRegisterHandler(FilterMessageType_PushHashDatabase, MhpHandlePushHashDatabase, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_PushPatternDatabase, MhpHandlePushPatternDatabase, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_PushSignatureDatabase, MhpHandlePushSignatureDatabase, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_PushIoCFeed, MhpHandlePushIoCFeed, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_PushWhitelist, MhpHandlePushWhitelist, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_UpdateBehavioralRules, MhpHandleUpdateBehavioralRules, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_PushNetworkIoC, MhpHandlePushNetworkIoC, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_ExclusionUpdate, MhpHandleExclusionUpdate, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    //
    // Mark as fully initialized
    //
    InterlockedExchange(&g_MhGlobals.InitState, MH_STATE_INITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Message handler initialized\n");

    return STATUS_SUCCESS;

CleanupOnError:
    //
    // Cleanup on initialization failure
    //
    if (g_MhGlobals.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside);
        g_MhGlobals.LookasideInitialized = FALSE;
    }

    InterlockedExchange(&g_MhGlobals.InitState, MH_STATE_UNINITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[ShadowStrike/MH] Initialization failed: 0x%08X\n", status);

    return status;
}

/**
 * @brief Shutdown the message handler subsystem.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MhShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    LONG state;

    PAGED_CODE();

    state = InterlockedCompareExchange(
        &g_MhGlobals.InitState,
        MH_STATE_UNINITIALIZED,
        MH_STATE_INITIALIZED
    );

    if (state != MH_STATE_INITIALIZED) {
        return;
    }

    //
    // Wait for all in-flight handler invocations to drain.
    // After InitState is UNINITIALIZED, no new invocations will start,
    // but existing ones may still be running.
    //
    {
        ULONG drainAttempts = 0;
        const ULONG maxDrainAttempts = 500;  // 5 seconds max
        BOOLEAN allDrained;

        do {
            allDrained = TRUE;
            for (ULONG i = 0; i < MH_MAX_HANDLERS; i++) {
                if (g_MhGlobals.Handlers[i].ActiveInvocations > 0) {
                    allDrained = FALSE;
                    break;
                }
            }

            if (!allDrained) {
                LARGE_INTEGER delay;
                delay.QuadPart = -100000;  // 10ms
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        } while (!allDrained && ++drainAttempts < maxDrainAttempts);

        if (!allDrained) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/MH] CRITICAL: Shutdown drain timeout - "
                       "handlers still active after %u attempts, "
                       "skipping resource cleanup to prevent BSOD\n",
                       drainAttempts);

            //
            // Active handlers may be traversing the protected process list
            // or allocating from the lookaside. Destroying these resources
            // now would cause pool corruption / use-after-free / BSOD.
            // Accept the pool leak — OS reclaims on driver unload.
            //
            return;
        }
    }

    //
    // Clear protected process list under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    while (!IsListEmpty(&g_MhGlobals.ProtectedProcessList)) {
        entry = RemoveHeadList(&g_MhGlobals.ProtectedProcessList);
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        ExFreeToNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside, protectedProcess);
    }
    g_MhGlobals.ProtectedProcessCount = 0;

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (g_MhGlobals.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside);
        g_MhGlobals.LookasideInitialized = FALSE;
    }

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Shutdown - Processed=%lld, Succeeded=%lld, Failed=%lld, Invalid=%lld, Unauthorized=%lld\n",
               g_MhGlobals.TotalMessagesProcessed,
               g_MhGlobals.TotalMessagesSucceeded,
               g_MhGlobals.TotalMessagesFailed,
               g_MhGlobals.TotalInvalidMessages,
               g_MhGlobals.TotalUnauthorizedAttempts);
}

// ============================================================================
// HANDLER REGISTRATION
// ============================================================================

/**
 * @brief Register a message handler callback.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhRegisterHandler(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ PMH_MESSAGE_HANDLER_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    ULONG slot;

    PAGED_CODE();

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((ULONG)MessageType >= MH_MAX_HANDLERS) {
        return STATUS_INVALID_PARAMETER;
    }

    slot = (ULONG)MessageType;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);

    if (g_MhGlobals.Handlers[slot].Registered) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();
        return STATUS_ALREADY_REGISTERED;
    }

    g_MhGlobals.Handlers[slot].MessageType = MessageType;
    g_MhGlobals.Handlers[slot].Callback = Callback;
    g_MhGlobals.Handlers[slot].Context = Context;
    g_MhGlobals.Handlers[slot].InvocationCount = 0;
    g_MhGlobals.Handlers[slot].ErrorCount = 0;
    g_MhGlobals.Handlers[slot].ActiveInvocations = 0;

    //
    // Memory barrier before setting Registered to ensure all fields are visible
    //
    MemoryBarrier();
    g_MhGlobals.Handlers[slot].Registered = TRUE;

    ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister a message handler.
 *
 * Waits for active invocations to complete before returning.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhUnregisterHandler(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    )
{
    ULONG slot;
    LONG activeCount;
    ULONG waitCount = 0;
    const ULONG maxWaitIterations = 1000;  // 10 seconds max
    LARGE_INTEGER delay;
    BOOLEAN timedOut = FALSE;

    PAGED_CODE();

    if ((ULONG)MessageType >= MH_MAX_HANDLERS) {
        return STATUS_INVALID_PARAMETER;
    }

    slot = (ULONG)MessageType;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);

    if (!g_MhGlobals.Handlers[slot].Registered) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Mark as unregistered first - new callers will see this
    //
    g_MhGlobals.Handlers[slot].Registered = FALSE;
    MemoryBarrier();

    //
    // Wait for active invocations to complete.
    // Release lock during sleep to avoid blocking dispatch.
    // Re-acquire before each check and before final cleanup.
    //
    while ((activeCount = g_MhGlobals.Handlers[slot].ActiveInvocations) > 0) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();

        if (++waitCount > maxWaitIterations) {
            //
            // Timeout waiting for callbacks to drain.
            // Re-acquire lock before falling through to cleanup.
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] Timeout waiting for handler %u to drain (active=%d)\n",
                       MessageType, activeCount);
            timedOut = TRUE;

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);
            break;
        }

        //
        // Wait 10ms and retry
        //
        delay.QuadPart = -100000;  // 10ms in 100ns units
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);
    }

    //
    // Clear the handler entry — lock is always held here
    //
    g_MhGlobals.Handlers[slot].Callback = NULL;
    g_MhGlobals.Handlers[slot].Context = NULL;

    ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    if (timedOut) {
        return STATUS_TIMEOUT;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// AUTHORIZATION
// ============================================================================

/**
 * @brief Check if the calling process is authorized for privileged operations.
 *
 * Authorization is granted if:
 * 1. Caller is running as LocalSystem, OR
 * 2. Caller is a registered protected ShadowStrike process
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
MhIsCallerAuthorized(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext
    )
{
    SECURITY_SUBJECT_CONTEXT subjectContext;
    PACCESS_TOKEN token;
    BOOLEAN isSystem = FALSE;
    PTOKEN_USER tokenUser = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (ClientContext == NULL) {
        return FALSE;
    }

    //
    // Check if this is the primary scanner connection (implicitly trusted)
    //
    if (ClientContext->IsPrimaryScanner) {
        return TRUE;
    }

    //
    // Check if caller's PID is in protected process list
    //
    if (ClientContext->ClientProcessId != NULL) {
        UINT32 pid = (UINT32)(ULONG_PTR)ClientContext->ClientProcessId;
        if (MhIsProcessProtected(pid)) {
            return TRUE;
        }
    }

    //
    // Check if caller is running as SYSTEM
    //
    SeCaptureSubjectContext(&subjectContext);
    token = SeQuerySubjectContextToken(&subjectContext);

    if (token != NULL) {
        status = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
        if (NT_SUCCESS(status) && tokenUser != NULL) {
            //
            // Check for LocalSystem SID (S-1-5-18)
            //
            SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
            UCHAR systemSidBuffer[SECURITY_MAX_SID_SIZE];
            PSID systemSid = (PSID)systemSidBuffer;

            status = RtlInitializeSid(systemSid, &ntAuthority, 1);
            if (NT_SUCCESS(status)) {
                *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
                isSystem = RtlEqualSid(tokenUser->User.Sid, systemSid);
            }

            ExFreePool(tokenUser);
        }
    }

    SeReleaseSubjectContext(&subjectContext);

    return isSystem;
}

/**
 * @brief Check if a message type requires authorization.
 */
static BOOLEAN
MhpIsPrivilegedOperation(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    )
{
    switch (MessageType) {
        case FilterMessageType_EnableFiltering:
        case FilterMessageType_DisableFiltering:
        case FilterMessageType_UpdatePolicy:
        case FilterMessageType_ConfigUpdate:
        case FilterMessageType_RegisterProtectedProcess:
        case FilterMessageType_PushHashDatabase:
        case FilterMessageType_PushPatternDatabase:
        case FilterMessageType_PushSignatureDatabase:
        case FilterMessageType_PushIoCFeed:
        case FilterMessageType_PushWhitelist:
        case FilterMessageType_UpdateBehavioralRules:
        case FilterMessageType_PushNetworkIoC:
        case FilterMessageType_ExclusionUpdate:
            return TRUE;
        default:
            return FALSE;
    }
}

// ============================================================================
// USER-MODE BUFFER HANDLING
// ============================================================================

/**
 * @brief Validate user buffer, probe it, and copy to kernel memory.
 *
 * This function:
 * 1. Probes the user buffer for read access
 * 2. Allocates a kernel buffer
 * 3. Copies the data under SEH protection
 * 4. Validates the message header
 *
 * On success, caller must free KernelBuffer with MhpFreeKernelBuffer().
 */
static NTSTATUS
MhpValidateAndCopyMessage(
    _In_reads_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PVOID* KernelBuffer,
    _Out_ PULONG KernelBufferSize,
    _Out_ PSS_MESSAGE_HEADER* Header,
    _Out_ PVOID* Payload,
    _Out_ PULONG PayloadSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID kernelBuf = NULL;
    PSS_MESSAGE_HEADER hdr;

    PAGED_CODE();

    *KernelBuffer = NULL;
    *KernelBufferSize = 0;
    *Header = NULL;
    *Payload = NULL;
    *PayloadSize = 0;

    //
    // Basic parameter validation
    //
    if (UserBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (UserBufferSize < sizeof(SS_MESSAGE_HEADER)) {
        return SHADOWSTRIKE_ERROR_BUFFER_TOO_SMALL;
    }

    if (UserBufferSize > MH_MAX_INPUT_BUFFER_SIZE) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    //
    // Allocate kernel buffer
    //
    kernelBuf = ExAllocatePool2(
        POOL_FLAG_PAGED | POOL_FLAG_UNINITIALIZED,
        UserBufferSize,
        MH_KERNEL_BUFFER_TAG
    );

    if (kernelBuf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Probe and copy under SEH
    //
    __try {
        //
        // Probe for read access - this validates the user pointer
        //
        ProbeForRead(UserBuffer, UserBufferSize, sizeof(UCHAR));

        //
        // Copy to kernel buffer
        //
        RtlCopyMemory(kernelBuf, UserBuffer, UserBufferSize);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return status;
    }

    //
    // Now validate the copied header (safe kernel memory)
    //
    hdr = (PSS_MESSAGE_HEADER)kernelBuf;

    //
    // Validate magic
    //
    if (hdr->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Validate version
    //
    if (hdr->Version != SHADOWSTRIKE_PROTOCOL_VERSION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Version mismatch: got %u, expected %u\n",
                   hdr->Version, SHADOWSTRIKE_PROTOCOL_VERSION);
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_VERSION_MISMATCH;
    }

    //
    // Validate sizes - prevent integer overflow
    //
    if (hdr->TotalSize > UserBufferSize) {
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Safe subtraction - we already validated UserBufferSize >= sizeof(SS_MESSAGE_HEADER)
    //
    ULONG maxPayloadSize = UserBufferSize - sizeof(SS_MESSAGE_HEADER);
    if (hdr->DataSize > maxPayloadSize) {
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Success - return kernel buffer and parsed pointers
    //
    *KernelBuffer = kernelBuf;
    *KernelBufferSize = UserBufferSize;
    *Header = hdr;

    if (hdr->DataSize > 0) {
        *Payload = (PUCHAR)kernelBuf + sizeof(SS_MESSAGE_HEADER);
        *PayloadSize = hdr->DataSize;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Free kernel buffer allocated by MhpValidateAndCopyMessage.
 */
static VOID
MhpFreeKernelBuffer(
    _In_ PVOID KernelBuffer
    )
{
    if (KernelBuffer != NULL) {
        ExFreePoolWithTag(KernelBuffer, MH_KERNEL_BUFFER_TAG);
    }
}

/**
 * @brief Copy output data to user buffer with SEH protection.
 */
static NTSTATUS
MhpCopyOutputToUser(
    _Out_writes_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (UserBuffer == NULL || Data == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize > UserBufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    __try {
        ProbeForWrite(UserBuffer, DataSize, sizeof(UCHAR));
        RtlCopyMemory(UserBuffer, Data, DataSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

// ============================================================================
// MAIN MESSAGE PROCESSING
// ============================================================================

/**
 * @brief Process a message from user-mode.
 *
 * This is the main entry point for handling messages. It:
 * 1. Validates parameters
 * 2. Copies input buffer to kernel memory with probing
 * 3. Validates message header
 * 4. Checks authorization for privileged operations
 * 5. Looks up and invokes the handler (outside the lock)
 * 6. Copies output back to user with probing
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProcessUserMessage(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PVOID kernelBuffer = NULL;
    ULONG kernelBufferSize = 0;
    PSS_MESSAGE_HEADER header = NULL;
    PVOID payload = NULL;
    ULONG payloadSize = 0;
    PMH_HANDLER_ENTRY handlerEntry = NULL;
    PMH_MESSAGE_HANDLER_CALLBACK callback = NULL;
    PVOID context = NULL;
    ULONG slot;
    UCHAR localOutputBuffer[MH_MAX_LOCAL_OUTPUT_SIZE];
    ULONG localOutputLength = 0;

    PAGED_CODE();

    //
    // Validate required parameters
    //
    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ClientContext == NULL) {
        *ReturnOutputBufferLength = 0;
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize output
    //
    *ReturnOutputBufferLength = 0;

    //
    // Check if initialized
    //
    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return SHADOWSTRIKE_ERROR_NOT_INITIALIZED;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MhGlobals.TotalMessagesProcessed);

    //
    // Validate and copy input buffer to kernel memory
    //
    status = MhpValidateAndCopyMessage(
        InputBuffer,
        InputBufferSize,
        &kernelBuffer,
        &kernelBufferSize,
        &header,
        &payload,
        &payloadSize
    );

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_MhGlobals.TotalInvalidMessages);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid message received: 0x%08X\n", status);
        return status;
    }

    //
    // Check authorization for privileged operations
    //
    if (MhpIsPrivilegedOperation((SHADOWSTRIKE_MESSAGE_TYPE)header->MessageType)) {
        if (!MhIsCallerAuthorized(ClientContext)) {
            InterlockedIncrement64(&g_MhGlobals.TotalUnauthorizedAttempts);
            MhpFreeKernelBuffer(kernelBuffer);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] Unauthorized attempt for message type %u from PID %p\n",
                       header->MessageType, ClientContext->ClientProcessId);

            return STATUS_ACCESS_DENIED;
        }
    }

    //
    // Look up handler
    //
    slot = (ULONG)header->MessageType;
    if (slot >= MH_MAX_HANDLERS) {
        InterlockedIncrement64(&g_MhGlobals.TotalUnhandledMessages);
        MhpFreeKernelBuffer(kernelBuffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Message type out of range: %u\n", header->MessageType);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get handler under shared lock, copy callback/context, then release lock
    // This prevents deadlock if callback tries to register/unregister handlers
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.HandlersLock);

    handlerEntry = &g_MhGlobals.Handlers[slot];
    if (handlerEntry->Registered && handlerEntry->Callback != NULL) {
        callback = handlerEntry->Callback;
        context = handlerEntry->Context;
        InterlockedIncrement(&handlerEntry->ActiveInvocations);
        InterlockedIncrement64(&handlerEntry->InvocationCount);
    }

    ExReleasePushLockShared(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    //
    // If no handler, not an error - just no handler registered
    //
    if (callback == NULL) {
        InterlockedIncrement64(&g_MhGlobals.TotalUnhandledMessages);
        MhpFreeKernelBuffer(kernelBuffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike/MH] No handler for message type: %u\n", header->MessageType);
        return STATUS_SUCCESS;
    }

    //
    // Call handler with kernel-mode buffers (safe).
    // Handlers write into the local stack buffer, which we then copy
    // to user-mode under SEH. Cap at MH_MAX_LOCAL_OUTPUT_SIZE.
    //
    RtlZeroMemory(localOutputBuffer, sizeof(localOutputBuffer));

    {
        ULONG effectiveOutputSize = 0;
        if (OutputBuffer != NULL) {
            effectiveOutputSize = min(OutputBufferSize, sizeof(localOutputBuffer));
            if (OutputBufferSize > sizeof(localOutputBuffer)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/MH] Output buffer %u exceeds local buffer %u, capping\n",
                           OutputBufferSize, (ULONG)sizeof(localOutputBuffer));
            }
        }

        status = callback(
            ClientContext,
            header,
            payload,
            payloadSize,
            (OutputBuffer != NULL) ? localOutputBuffer : NULL,
            effectiveOutputSize,
            &localOutputLength
        );
    }

    //
    // Decrement active invocations
    //
    InterlockedDecrement(&handlerEntry->ActiveInvocations);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&handlerEntry->ErrorCount);
    }

    //
    // Free kernel input buffer
    //
    MhpFreeKernelBuffer(kernelBuffer);
    kernelBuffer = NULL;

    //
    // Copy output to user buffer if needed
    //
    if (NT_SUCCESS(status) && OutputBuffer != NULL && localOutputLength > 0) {
        if (localOutputLength <= OutputBufferSize) {
            NTSTATUS copyStatus = MhpCopyOutputToUser(
                OutputBuffer,
                OutputBufferSize,
                localOutputBuffer,
                localOutputLength
            );

            if (NT_SUCCESS(copyStatus)) {
                *ReturnOutputBufferLength = localOutputLength;
            } else {
                //
                // Failed to copy output - don't fail the whole operation
                // as the handler already succeeded
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/MH] Failed to copy output to user: 0x%08X\n", copyStatus);
            }
        }
    }

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_MhGlobals.TotalMessagesSucceeded);
    } else {
        InterlockedIncrement64(&g_MhGlobals.TotalMessagesFailed);
    }

    return status;
}

// ============================================================================
// BUILT-IN HANDLERS
// ============================================================================

/**
 * @brief Handle heartbeat message.
 */
static NTSTATUS
MhpHandleHeartbeat(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Send simple acknowledgment reply if buffer provided
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;  // Success
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle configuration update message.
 *
 * This handler exists for backward compatibility but returns NOT_IMPLEMENTED
 * to indicate clients should use PolicyUpdate instead.
 */
static NTSTATUS
MhpHandleConfigUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] ConfigUpdate is deprecated - use PolicyUpdate instead\n");

    //
    // Return NOT_IMPLEMENTED to signal clients should migrate to PolicyUpdate
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)STATUS_NOT_IMPLEMENTED;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Handle policy update message.
 */
static NTSTATUS
MhpHandlePolicyUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_POLICY_UPDATE policy;
    PSHADOWSTRIKE_GENERIC_REPLY reply;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload size
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_POLICY_UPDATE)) {
        return STATUS_INVALID_PARAMETER;
    }

    policy = (PSHADOWSTRIKE_POLICY_UPDATE)PayloadBuffer;

    //
    // Validate policy values
    //
    if (policy->ScanTimeoutMs < SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS ||
        policy->ScanTimeoutMs > SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid scan timeout: %u (range: %u-%u)\n",
                   policy->ScanTimeoutMs,
                   SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS,
                   SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate MaxPendingRequests
    //
    if (policy->MaxPendingRequests == 0 || policy->MaxPendingRequests > 100000) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid MaxPendingRequests: %u\n",
                   policy->MaxPendingRequests);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Apply policy to driver configuration under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.ScanOnOpen = policy->ScanOnOpen;
    g_DriverData.Config.ScanOnExecute = policy->ScanOnExecute;
    g_DriverData.Config.ScanOnWrite = policy->ScanOnWrite;
    g_DriverData.Config.NotificationsEnabled = policy->EnableNotifications;
    g_DriverData.Config.BlockOnTimeout = policy->BlockOnTimeout;
    g_DriverData.Config.BlockOnError = policy->BlockOnError;
    g_DriverData.Config.ScanNetworkFiles = policy->ScanNetworkFiles;
    g_DriverData.Config.ScanRemovableMedia = policy->ScanRemovableMedia;
    g_DriverData.Config.MaxScanFileSize = policy->MaxScanFileSize;
    g_DriverData.Config.ScanTimeoutMs = policy->ScanTimeoutMs;
    g_DriverData.Config.CacheTTLSeconds = policy->CacheTTLSeconds;
    g_DriverData.Config.MaxPendingRequests = policy->MaxPendingRequests;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Apply message queue tuning if any values are non-zero.
    // Zero fields mean "keep current value" — MqConfigure handles this internally.
    //
    if (policy->MqMaxQueueDepth != 0 || policy->MqMaxMessageSize != 0 ||
        policy->MqBatchSize != 0 || policy->MqBatchTimeoutMs != 0) {

        NTSTATUS mqStatus = MqConfigure(
            policy->MqMaxQueueDepth,
            policy->MqMaxMessageSize,
            policy->MqBatchSize,
            policy->MqBatchTimeoutMs
        );
        if (!NT_SUCCESS(mqStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] MqConfigure failed: 0x%08X\n", mqStatus);
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Policy updated: ScanOnOpen=%d, ScanOnExec=%d, Timeout=%u\n",
               policy->ScanOnOpen, policy->ScanOnExecute, policy->ScanTimeoutMs);

    //
    // Audit trail: policy change affects entire protection posture
    //
    {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_PolicyUpdated,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)status;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return status;
}

/**
 * @brief Handle driver status query.
 */
static NTSTATUS
MhpHandleDriverStatusQuery(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    SHADOWSTRIKE_DRIVER_STATUS driverStatus;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Validate output buffer
    //
    if (OutputBuffer == NULL || OutputBufferSize < sizeof(SHADOWSTRIKE_DRIVER_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&driverStatus, sizeof(driverStatus));

    //
    // Fill driver status
    //
    driverStatus.VersionMajor = SHADOWSTRIKE_VERSION_MAJOR;
    driverStatus.VersionMinor = SHADOWSTRIKE_VERSION_MINOR;
    driverStatus.VersionBuild = SHADOWSTRIKE_VERSION_BUILD;

    //
    // Read config under shared lock for consistency
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ConfigLock);

    driverStatus.FilteringActive = g_DriverData.Config.FilteringEnabled && g_DriverData.FilteringStarted;
    driverStatus.ScanOnOpenEnabled = g_DriverData.Config.ScanOnOpen;
    driverStatus.ScanOnExecuteEnabled = g_DriverData.Config.ScanOnExecute;
    driverStatus.ScanOnWriteEnabled = g_DriverData.Config.ScanOnWrite;
    driverStatus.NotificationsEnabled = g_DriverData.Config.NotificationsEnabled;

    ExReleasePushLockShared(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Read statistics (volatile, no lock needed for approximate values)
    //
    driverStatus.TotalFilesScanned = (UINT64)g_DriverData.Stats.TotalFilesScanned;
    driverStatus.FilesBlocked = (UINT64)g_DriverData.Stats.FilesBlocked;
    driverStatus.CacheHits = (UINT64)g_DriverData.Stats.CacheHits;
    driverStatus.CacheMisses = (UINT64)g_DriverData.Stats.CacheMisses;
    driverStatus.PendingRequests = g_DriverData.Stats.PendingRequests;
    driverStatus.PeakPendingRequests = g_DriverData.Stats.PeakPendingRequests;
    driverStatus.ConnectedClients = g_DriverData.ConnectedClients;

    //
    // Compression transport statistics
    //
    {
        PCOMP_MANAGER compMgr = ShadowStrikeGetCompressionManager();
        if (compMgr != NULL) {
            COMP_STATISTICS compStats;
            NTSTATUS compStatus = CompGetStatistics(compMgr, &compStats);
            if (NT_SUCCESS(compStatus)) {
                driverStatus.CompressedMessages = compStats.TotalCompressed;
                driverStatus.CompressionBytesSaved = compStats.BytesSaved;
                driverStatus.CompressionAvgRatio = compStats.AverageRatio;
                driverStatus.CompressionErrors = (ULONG)compStats.Errors;
            }
        }
    }

    //
    // Message queue health statistics
    //
    {
        UINT64 mqEnqueued, mqDequeued, mqDropped;
        UINT32 mqDepth, mqPeak;

        NTSTATUS mqStatus = MqGetStatistics(
            &mqEnqueued, &mqDequeued, &mqDropped,
            &mqDepth, &mqPeak
        );
        if (NT_SUCCESS(mqStatus)) {
            driverStatus.MqTotalEnqueued = mqEnqueued;
            driverStatus.MqTotalDequeued = mqDequeued;
            driverStatus.MqTotalDropped = mqDropped;
            driverStatus.MqCurrentDepth = mqDepth;
            driverStatus.MqPeakDepth = mqPeak;
            driverStatus.MqFlowControlActive = MqIsHighWaterMark();
        }
    }

    //
    // ScanBridge health telemetry
    //
    {
        SB_STATISTICS sbStats;
        NTSTATUS sbStatus = ShadowStrikeGetScanBridgeStatistics(&sbStats);
        if (NT_SUCCESS(sbStatus)) {
            driverStatus.SbTotalScans = sbStats.TotalScanRequests;
            driverStatus.SbSuccessfulScans = sbStats.SuccessfulScans;
            driverStatus.SbFailedScans = sbStats.FailedScans;
            driverStatus.SbTimeoutScans = sbStats.TimeoutScans;
            driverStatus.SbCircuitBreakerTrips = (LONG64)sbStats.CircuitBreakerTrips;
            driverStatus.SbAvgLatencyMs = (sbStats.TotalScanRequests > 0)
                ? (ULONG)(sbStats.TotalLatencyMs / sbStats.TotalScanRequests)
                : 0;
        }
        driverStatus.SbCircuitState = (ULONG)ShadowStrikeGetCircuitState();
    }

    //
    // Telemetry Buffer health
    //
    {
        PTB_MANAGER tbMgr = ShadowStrikeGetTelemetryBuffer();
        if (tbMgr != NULL) {
            TB_STATISTICS tbStats;
            NTSTATUS tbStatus = TbGetStatistics(tbMgr, &tbStats);
            if (NT_SUCCESS(tbStatus)) {
                driverStatus.TbTotalEnqueued = (LONG64)tbStats.TotalEnqueued;
                driverStatus.TbTotalDequeued = (LONG64)tbStats.TotalDequeued;
                driverStatus.TbTotalDropped = (LONG64)tbStats.TotalDropped;
                driverStatus.TbTotalBytes = (LONG64)tbStats.TotalBytes;
                driverStatus.TbBatchesSent = (LONG64)tbStats.BatchesSent;
                driverStatus.TbUtilizationPercent = tbStats.UtilizationPercent;
                driverStatus.TbActiveCpuCount = tbStats.ActiveCpuCount;
            }
            driverStatus.TbBufferState = (ULONG)tbMgr->State;
        }
    }

    //
    // Instance context aggregate statistics (summed across all volumes)
    //
    {
        PFLT_INSTANCE instanceBuffer[32];
        ULONG actualCount = 0;
        NTSTATUS icStatus;

        icStatus = FltEnumerateInstances(
            NULL,
            g_DriverData.FilterHandle,
            instanceBuffer,
            ARRAYSIZE(instanceBuffer),
            &actualCount
        );

        if (NT_SUCCESS(icStatus)) {
            driverStatus.IcActiveInstances = actualCount;

            for (ULONG i = 0; i < actualCount; i++) {
                PSHADOW_INSTANCE_CONTEXT instCtx = NULL;

                if (NT_SUCCESS(FltGetInstanceContext(instanceBuffer[i], (PFLT_CONTEXT*)&instCtx))
                    && instCtx != NULL)
                {
                    driverStatus.IcTotalCreateOps += instCtx->TotalCreateOperations;
                    driverStatus.IcTotalScans += instCtx->TotalFilesScanned;
                    driverStatus.IcTotalBlocks += instCtx->TotalFilesBlocked;
                    driverStatus.IcTotalWrites += instCtx->TotalWriteOperations;
                    driverStatus.IcCleanVerdicts += instCtx->TotalCleanVerdicts;
                    driverStatus.IcMalwareVerdicts += instCtx->TotalMalwareVerdicts;
                    driverStatus.IcScanErrors += instCtx->TotalScanErrors;
                    driverStatus.IcCacheHits += instCtx->TotalCacheHits;
                    FltReleaseContext((PFLT_CONTEXT)instCtx);
                }

                FltObjectDereference(instanceBuffer[i]);
            }
        }
    }

    //
    // ETW Provider statistics
    //
    {
        UINT64 etwWritten = 0, etwDropped = 0, etwBytes = 0;
        if (NT_SUCCESS(EtwProviderGetStatistics(&etwWritten, &etwDropped, &etwBytes))) {
            driverStatus.EtwEventsWritten = etwWritten;
            driverStatus.EtwEventsDropped = etwDropped;
            driverStatus.EtwBytesWritten = etwBytes;
        }
    }

    //
    // Event schema statistics
    //
    {
        PES_SCHEMA schema = ShadowStrikeGetEventSchema();
        if (schema != NULL) {
            driverStatus.EventSchemaEventCount = (UINT32)EsGetEventCount(schema);
        }
    }

    //
    // Manifest generator statistics
    //
    {
        PMG_GENERATOR mg = ShadowStrikeGetManifestGenerator();
        if (mg != NULL) {
            MG_GENERATION_STATS mgStats;
            NTSTATUS mgStatStatus = MgGetStatistics(mg, &mgStats);
            if (NT_SUCCESS(mgStatStatus)) {
                driverStatus.ManifestChannelCount = mgStats.ChannelCount;
                driverStatus.ManifestKeywordCount = mgStats.KeywordCount;
                driverStatus.ManifestTaskCount = mgStats.TaskCount;
                driverStatus.ManifestValidationErrors = mgStats.ValidationErrors;
            }
        }
    }

    //
    // TelemetryEvents engine statistics
    //
    {
        TE_STATISTICS teStats;
        NTSTATUS teStatus = TeGetStatistics(&teStats);
        if (NT_SUCCESS(teStatus)) {
            driverStatus.TeEventsGenerated = teStats.EventsGenerated;
            driverStatus.TeEventsThrottled = teStats.EventsThrottled;
            driverStatus.TeAllocationFailures = teStats.AllocationFailures;
            driverStatus.TePeakEventsPerSecond = teStats.PeakEventsPerSecond;
            driverStatus.TeThrottleActivations = teStats.ThrottleActivations;
        }
        driverStatus.TeThrottleAction = (LONG)TeGetState();
    }

    //
    // ExclusionManager statistics
    //
    {
        SHADOWSTRIKE_EXCLUSION_STATS exclStats;
        ShadowStrikeExclusionGetStats(&exclStats);
        driverStatus.ExclTotalChecks = exclStats.TotalChecks;
        driverStatus.ExclPathMatches = exclStats.PathMatches;
        driverStatus.ExclExtensionMatches = exclStats.ExtensionMatches;
        driverStatus.ExclProcessMatches = exclStats.ProcessNameMatches;
        driverStatus.ExclPidMatches = exclStats.PidMatches;
        driverStatus.ExclTotalBypassed = exclStats.TotalBypassed;
        driverStatus.ExclPathCount = exclStats.PathExclusionCount;
        driverStatus.ExclExtensionCount = exclStats.ExtensionExclusionCount;
        driverStatus.ExclProcessCount = exclStats.ProcessExclusionCount;
        driverStatus.ExclPidCount = exclStats.PidExclusionCount;
    }

    //
    // Process Exclusion Engine statistics (trusted PID bitmap/hash)
    //
    {
        PE_EXCLUSION_STATS peStats;
        ShadowStrikeProcessExclusionGetStats(&peStats);
        driverStatus.ProcExclTotalLookups       = peStats.TotalLookups;
        driverStatus.ProcExclBitmapHits         = peStats.BitmapHits;
        driverStatus.ProcExclHashHits           = peStats.HashHits;
        driverStatus.ProcExclMisses             = peStats.Misses;
        driverStatus.ProcExclProcessesExcluded  = peStats.ProcessesExcluded;
        driverStatus.ProcExclInheritedExclusions= peStats.InheritedExclusions;
        driverStatus.ProcExclCurrentBitmapCount = peStats.CurrentBitmapCount;
        driverStatus.ProcExclCurrentHashCount   = peStats.CurrentHashCount;
    }

    //
    // Hollowing Detector stats
    //
    {
        PH_STATISTICS phStats;
        if (NT_SUCCESS(MmMonitorGetHollowingStats(&phStats))) {
            driverStatus.HollowProcessesAnalyzed     = (LONG64)phStats.ProcessesAnalyzed;
            driverStatus.HollowDetections            = (LONG64)phStats.HollowingDetected;
            driverStatus.HollowDoppelgangingDetected = (LONG64)phStats.DoppelgangingDetected;
            driverStatus.HollowGhostingDetected      = (LONG64)phStats.GhostingDetected;
        }
    }

    //
    // Injection Detector stats
    //
    {
        INJ_STATISTICS injStats;
        if (NT_SUCCESS(MmMonitorGetInjectionStats(&injStats))) {
            driverStatus.InjTotalOperations   = (LONG64)injStats.TotalOperations;
            driverStatus.InjDetectedInjections = (LONG64)injStats.DetectedInjections;
            driverStatus.InjBlockedInjections  = (LONG64)injStats.BlockedInjections;
            driverStatus.InjActiveChains       = (LONG64)injStats.ActiveChains;
        }
    }

    //
    // Memory Monitor aggregate stats
    //
    {
        MEMORY_MONITOR_STATISTICS mmStats;
        if (NT_SUCCESS(MmMonitorGetStatistics(&mmStats))) {
            driverStatus.MemMonEventsProcessed     = mmStats.TotalEventsProcessed;
            driverStatus.MemMonShellcodeDetections  = mmStats.TotalShellcodeDetections;
            driverStatus.MemMonHeapSprayDetections  = mmStats.TotalHeapSprayDetections;
            driverStatus.MemMonROPDetections        = mmStats.TotalROPDetections;
            driverStatus.MemMonSectionAnomalies     = mmStats.TotalSectionAnomalies;
            driverStatus.MemMonEventsDropped        = mmStats.EventsDropped;
            driverStatus.MemMonProcessContexts      = (LONG)mmStats.ProcessContextCount;
            driverStatus.MemMonEnabled              = mmStats.Enabled;
        }
    }

    //
    // Memory Scanner stats (MS-H4 fix)
    //
    {
        PMS_SCANNER msScanner = ShadowStrikeGetMemoryScanner();
        if (msScanner != NULL) {
            MS_STATISTICS msStats;
            if (NT_SUCCESS(MsGetStatistics(msScanner, &msStats))) {
                driverStatus.MsScannerTotalScans     = (LONG64)msStats.TotalScans;
                driverStatus.MsScannerTotalMatches   = (LONG64)msStats.TotalMatches;
                driverStatus.MsScannerBytesScanned   = (LONG64)msStats.BytesScanned;
                driverStatus.MsScannerTimeouts       = (LONG64)msStats.Timeouts;
                driverStatus.MsScannerPatternCount   = msStats.PatternCount;
                driverStatus.MsScannerActiveScans    = msStats.ActiveScans;
                driverStatus.MsScannerAvgScanTimeMs  = msStats.AverageScanTimeMs;
            }
        }
    }

    //
    // Copy to output buffer (already validated as kernel memory by caller)
    //
    RtlCopyMemory(OutputBuffer, &driverStatus, sizeof(driverStatus));
    *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_DRIVER_STATUS);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle protected process registration.
 */
static NTSTATUS
MhpHandleProtectedProcessRegister(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_PROTECTED_PROCESS request;
    PSHADOWSTRIKE_GENERIC_REPLY reply;
    PMH_PROTECTED_PROCESS newEntry = NULL;
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS existingEntry;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN found = FALSE;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_PROTECTED_PROCESS)) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (PSHADOWSTRIKE_PROTECTED_PROCESS)PayloadBuffer;

    //
    // Validate process ID
    //
    if (request->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire exclusive lock for the entire operation to prevent race
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    //
    // Check limit INSIDE the lock to prevent race condition
    //
    if (g_MhGlobals.ProtectedProcessCount >= MH_MAX_PROTECTED_PROCESSES) {
        ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Max protected processes reached (%d)\n",
                   MH_MAX_PROTECTED_PROCESSES);
        return SHADOWSTRIKE_ERROR_MAX_PROTECTED;
    }

    //
    // Check if already registered
    //
    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        existingEntry = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (existingEntry->ProcessId == request->ProcessId) {
            //
            // Update existing entry
            //
            existingEntry->ProtectionFlags = request->ProtectionFlags;

            //
            // Copy ProcessName with guaranteed null-termination
            //
            RtlCopyMemory(
                existingEntry->ProcessName,
                request->ProcessName,
                sizeof(existingEntry->ProcessName) - sizeof(WCHAR)
            );
            existingEntry->ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = L'\0';

            found = TRUE;
            break;
        }
    }

    if (!found) {
        //
        // Allocate new entry from lookaside list
        //
        newEntry = (PMH_PROTECTED_PROCESS)ExAllocateFromNPagedLookasideList(
            &g_MhGlobals.ProtectedProcessLookaside);

        if (newEntry == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            RtlZeroMemory(newEntry, sizeof(MH_PROTECTED_PROCESS));
            newEntry->ProcessId = request->ProcessId;
            newEntry->ProtectionFlags = request->ProtectionFlags;
            KeQuerySystemTime(&newEntry->RegistrationTime);

            //
            // Copy ProcessName with guaranteed null-termination
            //
            RtlCopyMemory(
                newEntry->ProcessName,
                request->ProcessName,
                sizeof(newEntry->ProcessName) - sizeof(WCHAR)
            );
            newEntry->ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = L'\0';

            InsertTailList(&g_MhGlobals.ProtectedProcessList, &newEntry->ListEntry);
            InterlockedIncrement(&g_MhGlobals.ProtectedProcessCount);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MH] Protected process registered: PID=%u, Flags=0x%08X\n",
                       request->ProcessId, request->ProtectionFlags);

            //
            // Forward registration to ObjectCallback for handle access protection.
            // Map ProtectionFlags to Category/ProtectionLevel with safe defaults.
            //
            {
                NTSTATUS obStatus;
                obStatus = ObAddProtectedProcess(
                    ULongToHandle(request->ProcessId),
                    PpCategoryUserDefined,
                    PpProtectionMedium,
                    NULL
                );

                if (!NT_SUCCESS(obStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "[ShadowStrike/MH] ObAddProtectedProcess failed for PID=%u: 0x%08X\n",
                        request->ProcessId, obStatus);
                }
            }
        }
    }

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)status;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return status;
}

/**
 * @brief Handle scan verdict message (response to a scan request).
 */
static NTSTATUS
MhpHandleScanVerdict(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_SCAN_VERDICT_REPLY verdict;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)) {
        return STATUS_INVALID_PARAMETER;
    }

    verdict = (PSHADOWSTRIKE_SCAN_VERDICT_REPLY)PayloadBuffer;

    //
    // Route to MessageQueue completion mechanism
    // This completes the blocking message waiting for this verdict
    //
    status = MqCompleteMessage(
        verdict->MessageId,
        STATUS_SUCCESS,
        verdict,
        PayloadSize
    );

    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Failed to complete scan verdict: id=%llu, status=0x%08X\n",
                   verdict->MessageId, status);
    }

    //
    // Update statistics
    //
    SHADOWSTRIKE_INC_STAT(RepliesReceived);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle enable filtering command.
 */
static NTSTATUS
MhpHandleEnableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Enable filtering under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = TRUE;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Filtering enabled\n");

    //
    // Audit trail: filtering state change
    //
    {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_FilteringEnabled,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle disable filtering command.
 */
static NTSTATUS
MhpHandleDisableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Disable filtering under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = FALSE;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Filtering disabled\n");

    //
    // Audit trail: filtering disabled is a defense-critical event.
    // Submit to BehaviorEngine so attack chain tracker can correlate
    // with subsequent evasion attempts if the agent was compromised.
    //
    {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_FilteringDisabled,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PROTECTED PROCESS QUERIES
// ============================================================================

/**
 * @brief Check if a process is protected.
 *
 * Safe to call from IRQL <= APC_LEVEL.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MhIsProcessProtected(
    _In_ UINT32 ProcessId
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    BOOLEAN found = FALSE;

    if (ProcessId == 0) {
        return FALSE;
    }

    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return found;
}

/**
 * @brief Get protection flags for a process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MhGetProcessProtectionFlags(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 Flags
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = 0;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return SHADOWSTRIKE_ERROR_NOT_INITIALIZED;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            *Flags = protectedProcess->ProtectionFlags;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockShared(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return status;
}

/**
 * @brief Remove a protected process (e.g., on process termination).
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MhUnprotectProcess(
    _In_ UINT32 ProcessId
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return SHADOWSTRIKE_ERROR_NOT_INITIALIZED;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            RemoveEntryList(&protectedProcess->ListEntry);
            ExFreeToNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside, protectedProcess);
            InterlockedDecrement(&g_MhGlobals.ProtectedProcessCount);
            status = STATUS_SUCCESS;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MH] Protected process removed: PID=%u\n", ProcessId);

            //
            // Also remove from ObjectCallback's protected process list
            //
            ObRemoveProtectedProcess(ULongToHandle(ProcessId));

            break;
        }
    }

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return status;
}

// ============================================================================
// DATA PUSH HANDLER IMPLEMENTATIONS
// ============================================================================
//
// These handlers receive batched threat intelligence data from the user-mode
// agent and route entries to the appropriate kernel detection modules.
//
// Wire format: SHADOWSTRIKE_PUSH_BATCH_HEADER + N * entry structs
//
// All handlers follow this pattern:
//   1. Validate payload >= sizeof(batch header)
//   2. Validate batch header (entry count, sizes, flags)
//   3. Get target module instance via accessor
//   4. Iterate entries, convert wire format → module API, call loading API
//   5. Build push reply with accepted/rejected counts
//

C_ASSERT(sizeof(SHADOWSTRIKE_PUSH_REPLY) <= MH_MAX_LOCAL_OUTPUT_SIZE);

/**
 * @brief Common batch header validation.
 *
 * Validates the batch header fields and calculates expected payload size.
 *
 * @return STATUS_SUCCESS if valid, error status otherwise.
 */
static NTSTATUS
MhpValidateBatchHeader(
    _In_reads_bytes_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _In_ ULONG FixedEntrySize,
    _Out_ PSHADOWSTRIKE_PUSH_BATCH_HEADER* BatchHeader,
    _Out_ PVOID* EntriesStart,
    _Out_ PULONG EntryCount
    )
{
    PSHADOWSTRIKE_PUSH_BATCH_HEADER header;
    ULONG expectedSize;
    ULONG entriesOffset;

    PAGED_CODE();

    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (PSHADOWSTRIKE_PUSH_BATCH_HEADER)PayloadBuffer;

    //
    // Validate entry count bounds
    //
    if (header->EntryCount == 0) {
        if (header->Flags & SHADOWSTRIKE_PUSH_FLAG_CLEAR) {
            // Clear operation with zero entries is valid
            *BatchHeader = header;
            *EntriesStart = NULL;
            *EntryCount = 0;
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;
    }

    if (header->EntryCount > SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Push batch too large: %u entries (max %u)\n",
                   header->EntryCount, SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // For fixed-size entries, validate total payload size
    //
    entriesOffset = sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER);

    if (FixedEntrySize > 0) {
        //
        // Check for multiplication overflow
        //
        if (header->EntryCount > (MAXULONG - entriesOffset) / FixedEntrySize) {
            return STATUS_INTEGER_OVERFLOW;
        }
        expectedSize = entriesOffset + (header->EntryCount * FixedEntrySize);
        if (PayloadSize < expectedSize) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] Push payload too small: %u bytes, need %u\n",
                       PayloadSize, expectedSize);
            return STATUS_BUFFER_TOO_SMALL;
        }
    } else {
        //
        // Variable-size entries: validate TotalDataSize
        //
        if (header->TotalDataSize == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (header->TotalDataSize > (MAXULONG - entriesOffset)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        expectedSize = entriesOffset + header->TotalDataSize;
        if (PayloadSize < expectedSize) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] Push payload too small: %u bytes, need %u\n",
                       PayloadSize, expectedSize);
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    *BatchHeader = header;
    *EntriesStart = (PUCHAR)PayloadBuffer + entriesOffset;
    *EntryCount = header->EntryCount;

    return STATUS_SUCCESS;
}

/**
 * @brief Build and write push reply to output buffer.
 */
static VOID
MhpBuildPushReply(
    _In_ PSS_MESSAGE_HEADER Header,
    _In_ NTSTATUS Status,
    _In_ ULONG Accepted,
    _In_ ULONG Rejected,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_PUSH_REPLY reply;

    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_PUSH_REPLY)) {
        reply = (PSHADOWSTRIKE_PUSH_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)Status;
        reply->EntriesAccepted = Accepted;
        reply->EntriesRejected = Rejected;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_PUSH_REPLY);
    } else {
        *ReturnOutputBufferLength = 0;
    }
}

/**
 * @brief Handle hash database push (FilterMessageType_PushHashDatabase).
 *
 * Converts SHADOWSTRIKE_PUSH_HASH_ENTRY to IOM_IOC_INPUT and loads
 * each entry into the IOCMatcher via IomLoadIOC().
 */
static NTSTATUS
MhpHandlePushHashDatabase(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PIOM_MATCHER matcher;
    PSHADOWSTRIKE_PUSH_HASH_ENTRY entry;
    IOM_IOC_INPUT iocInput;
    ULONG i;
    ULONG hashLen;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize,
        sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY),
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    matcher = BeGetIocMatcher();
    if (matcher == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] PushHashDatabase: IOCMatcher not available\n");
        MhpBuildPushReply(Header, STATUS_DEVICE_NOT_READY, 0, entryCount,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_DEVICE_NOT_READY;
    }

    entry = (PSHADOWSTRIKE_PUSH_HASH_ENTRY)entriesStart;

    for (i = 0; i < entryCount; i++) {
        RtlZeroMemory(&iocInput, sizeof(iocInput));

        //
        // Convert hash type to hex string representation for IOCMatcher value
        //
        switch (entry->HashType) {
            case 0: hashLen = 16; break;  // MD5
            case 1: hashLen = 20; break;  // SHA1
            case 2: hashLen = 32; break;  // SHA256
            default:
                rejected++;
                entry++;
                continue;
        }

        //
        // Build hex string from hash bytes
        //
        iocInput.ValueLength = hashLen * 2;
        if (iocInput.ValueLength >= IOM_MAX_IOC_LENGTH) {
            rejected++;
            entry++;
            continue;
        }

        for (ULONG b = 0; b < hashLen; b++) {
            UCHAR hi = (entry->Hash[b] >> 4) & 0x0F;
            UCHAR lo = entry->Hash[b] & 0x0F;
            iocInput.Value[b * 2]     = (CHAR)(hi < 10 ? '0' + hi : 'a' + hi - 10);
            iocInput.Value[b * 2 + 1] = (CHAR)(lo < 10 ? '0' + lo : 'a' + lo - 10);
        }
        iocInput.Value[iocInput.ValueLength] = '\0';

        //
        // Map hash type to IOC type using proper enum values
        //
        switch (entry->HashType) {
            case 0: iocInput.Type = IomType_FileHash_MD5; break;
            case 1: iocInput.Type = IomType_FileHash_SHA1; break;
            case 2: iocInput.Type = IomType_FileHash_SHA256; break;
            default: iocInput.Type = IomType_FileHash_SHA256; break;
        }

        iocInput.Severity = (IOM_SEVERITY)entry->Severity;
        iocInput.MatchMode = (IOM_MATCH_MODE)0;  // Exact match
        iocInput.CaseSensitive = FALSE;  // Hex hashes are case-insensitive
        iocInput.Expiry = entry->Expiry;

        //
        // Copy threat name (ensure null termination)
        //
        RtlCopyMemory(iocInput.ThreatName, entry->ThreatName,
                       min(sizeof(entry->ThreatName), IOM_MAX_THREAT_NAME_LENGTH - 1));
        iocInput.ThreatName[IOM_MAX_THREAT_NAME_LENGTH - 1] = '\0';

        RtlStringCbCopyA(iocInput.Source, sizeof(iocInput.Source), "UserModeAgent");

        status = IomLoadIOC(matcher, &iocInput);
        if (NT_SUCCESS(status)) {
            accepted++;
        } else {
            rejected++;
        }

        entry++;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] PushHashDatabase: %u accepted, %u rejected\n",
               accepted, rejected);

    //
    // Audit trail: threat intel modification changes detection capability
    //
    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ThreatIntelPushed,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle pattern database push (FilterMessageType_PushPatternDatabase).
 *
 * Patterns are loaded into IOCMatcher with pattern-appropriate IOC types
 * (YARA for binary patterns) and wildcard/regex match modes.
 * Unlike hash push which uses exact matching, patterns use content-based matching.
 */
static NTSTATUS
MhpHandlePushPatternDatabase(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PIOM_MATCHER matcher;
    PSHADOWSTRIKE_PUSH_HASH_ENTRY entry;
    IOM_IOC_INPUT iocInput;
    ULONG i;
    ULONG hashLen;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize,
        sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY),
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    matcher = BeGetIocMatcher();
    if (matcher == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] PushPatternDatabase: IOCMatcher not available\n");
        MhpBuildPushReply(Header, STATUS_DEVICE_NOT_READY, 0, entryCount,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_DEVICE_NOT_READY;
    }

    entry = (PSHADOWSTRIKE_PUSH_HASH_ENTRY)entriesStart;

    for (i = 0; i < entryCount; i++) {
        RtlZeroMemory(&iocInput, sizeof(iocInput));

        switch (entry->HashType) {
            case 0: hashLen = 16; break;
            case 1: hashLen = 20; break;
            case 2: hashLen = 32; break;
            default:
                rejected++;
                entry++;
                continue;
        }

        iocInput.ValueLength = hashLen * 2;
        if (iocInput.ValueLength >= IOM_MAX_IOC_LENGTH) {
            rejected++;
            entry++;
            continue;
        }

        for (ULONG b = 0; b < hashLen; b++) {
            UCHAR hi = (entry->Hash[b] >> 4) & 0x0F;
            UCHAR lo = entry->Hash[b] & 0x0F;
            iocInput.Value[b * 2]     = (CHAR)(hi < 10 ? '0' + hi : 'a' + hi - 10);
            iocInput.Value[b * 2 + 1] = (CHAR)(lo < 10 ? '0' + lo : 'a' + lo - 10);
        }
        iocInput.Value[iocInput.ValueLength] = '\0';

        //
        // Patterns use YARA type with wildcard matching mode.
        // This distinguishes them from exact hash matches and
        // enables the IOCMatcher to use pattern-aware comparison.
        //
        iocInput.Type = IomType_YARA;
        iocInput.Severity = (IOM_SEVERITY)entry->Severity;
        iocInput.MatchMode = IomMatchMode_Wildcard;
        iocInput.CaseSensitive = FALSE;
        iocInput.Expiry = entry->Expiry;

        RtlCopyMemory(iocInput.ThreatName, entry->ThreatName,
                       min(sizeof(entry->ThreatName), IOM_MAX_THREAT_NAME_LENGTH - 1));
        iocInput.ThreatName[IOM_MAX_THREAT_NAME_LENGTH - 1] = '\0';

        RtlStringCbCopyA(iocInput.Source, sizeof(iocInput.Source), "PatternDB");

        status = IomLoadIOC(matcher, &iocInput);
        if (NT_SUCCESS(status)) {
            accepted++;
        } else {
            rejected++;
        }

        entry++;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] PushPatternDatabase: %u accepted, %u rejected\n",
               accepted, rejected);

    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ThreatIntelPushed,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle signature database push (FilterMessageType_PushSignatureDatabase).
 *
 * Signatures are loaded into IOCMatcher with file-name type and exact
 * matching. This enables signature-based file identification by name/path.
 * Distinguished from hash push (binary content match) and pattern push (YARA/wildcard).
 */
static NTSTATUS
MhpHandlePushSignatureDatabase(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PIOM_MATCHER matcher;
    PSHADOWSTRIKE_PUSH_HASH_ENTRY entry;
    IOM_IOC_INPUT iocInput;
    ULONG i;
    ULONG hashLen;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize,
        sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY),
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    matcher = BeGetIocMatcher();
    if (matcher == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] PushSignatureDatabase: IOCMatcher not available\n");
        MhpBuildPushReply(Header, STATUS_DEVICE_NOT_READY, 0, entryCount,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_DEVICE_NOT_READY;
    }

    entry = (PSHADOWSTRIKE_PUSH_HASH_ENTRY)entriesStart;

    for (i = 0; i < entryCount; i++) {
        RtlZeroMemory(&iocInput, sizeof(iocInput));

        switch (entry->HashType) {
            case 0: hashLen = 16; break;
            case 1: hashLen = 20; break;
            case 2: hashLen = 32; break;
            default:
                rejected++;
                entry++;
                continue;
        }

        iocInput.ValueLength = hashLen * 2;
        if (iocInput.ValueLength >= IOM_MAX_IOC_LENGTH) {
            rejected++;
            entry++;
            continue;
        }

        for (ULONG b = 0; b < hashLen; b++) {
            UCHAR hi = (entry->Hash[b] >> 4) & 0x0F;
            UCHAR lo = entry->Hash[b] & 0x0F;
            iocInput.Value[b * 2]     = (CHAR)(hi < 10 ? '0' + hi : 'a' + hi - 10);
            iocInput.Value[b * 2 + 1] = (CHAR)(lo < 10 ? '0' + lo : 'a' + lo - 10);
        }
        iocInput.Value[iocInput.ValueLength] = '\0';

        //
        // Signatures use Custom type with exact matching.
        // Custom type distinguishes signature-database entries from
        // file hash IOCs and pattern IOCs in the matcher's type buckets.
        //
        iocInput.Type = IomType_Custom;
        iocInput.Severity = (IOM_SEVERITY)entry->Severity;
        iocInput.MatchMode = IomMatchMode_Exact;
        iocInput.CaseSensitive = FALSE;
        iocInput.Expiry = entry->Expiry;

        RtlCopyMemory(iocInput.ThreatName, entry->ThreatName,
                       min(sizeof(entry->ThreatName), IOM_MAX_THREAT_NAME_LENGTH - 1));
        iocInput.ThreatName[IOM_MAX_THREAT_NAME_LENGTH - 1] = '\0';

        RtlStringCbCopyA(iocInput.Source, sizeof(iocInput.Source), "SignatureDB");

        status = IomLoadIOC(matcher, &iocInput);
        if (NT_SUCCESS(status)) {
            accepted++;
        } else {
            rejected++;
        }

        entry++;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] PushSignatureDatabase: %u accepted, %u rejected\n",
               accepted, rejected);

    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ThreatIntelPushed,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle IoC feed push (FilterMessageType_PushIoCFeed).
 *
 * Variable-length entries containing IoC indicators of any type.
 * Each entry is converted to IOM_IOC_INPUT and loaded via IomLoadIOC().
 */
static NTSTATUS
MhpHandlePushIoCFeed(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PIOM_MATCHER matcher;
    PSHADOWSTRIKE_PUSH_IOC_ENTRY entry;
    IOM_IOC_INPUT iocInput;
    ULONG i;
    PUCHAR cursor;
    PUCHAR payloadEnd;
    ULONG entryTotalSize;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Variable-size entries: pass 0 for fixed entry size
    //
    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize, 0,
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    matcher = BeGetIocMatcher();
    if (matcher == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] PushIoCFeed: IOCMatcher not available\n");
        MhpBuildPushReply(Header, STATUS_DEVICE_NOT_READY, 0, entryCount,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_DEVICE_NOT_READY;
    }

    cursor = (PUCHAR)entriesStart;
    payloadEnd = (PUCHAR)PayloadBuffer + PayloadSize;

    for (i = 0; i < entryCount; i++) {
        //
        // Validate we have at least the fixed header portion
        //
        if (cursor + sizeof(SHADOWSTRIKE_PUSH_IOC_ENTRY) > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        entry = (PSHADOWSTRIKE_PUSH_IOC_ENTRY)cursor;

        //
        // Validate value length doesn't exceed maximum
        //
        if (entry->ValueLength == 0 || entry->ValueLength >= IOM_MAX_IOC_LENGTH) {
            rejected++;
            //
            // Calculate entry total size to advance cursor
            //
            entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_IOC_ENTRY) + entry->ValueLength;
            if (cursor + entryTotalSize > payloadEnd) {
                rejected += (entryCount - i - 1);
                break;
            }
            cursor += entryTotalSize;
            continue;
        }

        entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_IOC_ENTRY) + entry->ValueLength;

        //
        // Validate variable data fits
        //
        if (cursor + entryTotalSize > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        //
        // Convert to IOM_IOC_INPUT
        //
        RtlZeroMemory(&iocInput, sizeof(iocInput));

        iocInput.Type = (IOM_IOC_TYPE)entry->Type;
        iocInput.Severity = (IOM_SEVERITY)entry->Severity;
        iocInput.MatchMode = (IOM_MATCH_MODE)entry->MatchMode;
        iocInput.CaseSensitive = (BOOLEAN)entry->CaseSensitive;
        iocInput.Expiry = entry->Expiry;

        //
        // Copy value from variable portion
        //
        iocInput.ValueLength = entry->ValueLength;
        RtlCopyMemory(iocInput.Value,
                       (PUCHAR)entry + sizeof(SHADOWSTRIKE_PUSH_IOC_ENTRY),
                       entry->ValueLength);
        iocInput.Value[entry->ValueLength] = '\0';

        //
        // Copy threat name and source (ensure null termination)
        //
        RtlCopyMemory(iocInput.ThreatName, entry->ThreatName,
                       min(sizeof(entry->ThreatName), IOM_MAX_THREAT_NAME_LENGTH - 1));
        iocInput.ThreatName[IOM_MAX_THREAT_NAME_LENGTH - 1] = '\0';

        RtlCopyMemory(iocInput.Source, entry->Source,
                       min(sizeof(entry->Source), IOM_MAX_SOURCE_LENGTH - 1));
        iocInput.Source[IOM_MAX_SOURCE_LENGTH - 1] = '\0';

        status = IomLoadIOC(matcher, &iocInput);
        if (NT_SUCCESS(status)) {
            accepted++;
        } else {
            rejected++;
        }

        cursor += entryTotalSize;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] PushIoCFeed: %u accepted, %u rejected\n",
               accepted, rejected);

    //
    // Audit trail: IOC feed updates are critical threat intel changes
    //
    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ThreatIntelPushed,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle whitelist push (FilterMessageType_PushWhitelist).
 *
 * Adds whitelisted entries to the ExclusionManager with system-level flags.
 * Hash-based entries add process exclusions; path entries add path exclusions.
 */
static NTSTATUS
MhpHandlePushWhitelist(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PSHADOWSTRIKE_PUSH_WHITELIST_ENTRY entry;
    ULONG i;
    PUCHAR cursor;
    PUCHAR payloadEnd;
    ULONG entryTotalSize;
    UNICODE_STRING valueString;
    WCHAR localBuffer[260];

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Variable-size entries (path/name entries have trailing WCHARs)
    //
    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize, 0,
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Handle clear flag
    //
    if (batchHeader->Flags & SHADOWSTRIKE_PUSH_FLAG_CLEAR) {
        ShadowStrikeClearExclusions(ShadowStrikeExclusionPath);
        ShadowStrikeClearExclusions(ShadowStrikeExclusionExtension);
        ShadowStrikeClearExclusions(ShadowStrikeExclusionProcessName);
    }

    if (entryCount == 0) {
        MhpBuildPushReply(Header, STATUS_SUCCESS, 0, 0,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_SUCCESS;
    }

    cursor = (PUCHAR)entriesStart;
    payloadEnd = (PUCHAR)PayloadBuffer + PayloadSize;

    for (i = 0; i < entryCount; i++) {
        if (cursor + sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY) > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        entry = (PSHADOWSTRIKE_PUSH_WHITELIST_ENTRY)cursor;

        //
        // Calculate total entry size
        //
        entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY);
        if (entry->EntryType != SHADOWSTRIKE_WL_TYPE_HASH) {
            if (entry->ValueLength > 0 && entry->ValueLength <= 259) {
                entryTotalSize += entry->ValueLength * sizeof(WCHAR);
            } else if (entry->ValueLength > 259) {
                rejected++;
                entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY) + entry->ValueLength * sizeof(WCHAR);
                if (cursor + entryTotalSize <= payloadEnd) {
                    cursor += entryTotalSize;
                } else {
                    rejected += (entryCount - i - 1);
                    break;
                }
                continue;
            }
        }

        if (cursor + entryTotalSize > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        switch (entry->EntryType) {
            case SHADOWSTRIKE_WL_TYPE_PATH:
            {
                if (entry->ValueLength == 0 || entry->ValueLength > 259) {
                    rejected++;
                    break;
                }
                PWCHAR valueData = (PWCHAR)((PUCHAR)entry + sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY));
                RtlCopyMemory(localBuffer, valueData, entry->ValueLength * sizeof(WCHAR));
                localBuffer[entry->ValueLength] = L'\0';
                valueString.Buffer = localBuffer;
                valueString.Length = entry->ValueLength * sizeof(WCHAR);
                valueString.MaximumLength = (entry->ValueLength + 1) * sizeof(WCHAR);

                status = ShadowStrikeAddPathExclusion(
                    &valueString,
                    entry->Flags | (UINT8)ShadowStrikeExclusionFlagSystem,
                    0  // Permanent
                );
                if (NT_SUCCESS(status)) {
                    accepted++;
                } else {
                    rejected++;
                }
                break;
            }

            case SHADOWSTRIKE_WL_TYPE_PROCESS:
            {
                if (entry->ValueLength == 0 || entry->ValueLength > 259) {
                    rejected++;
                    break;
                }
                PWCHAR valueData = (PWCHAR)((PUCHAR)entry + sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY));
                RtlCopyMemory(localBuffer, valueData, entry->ValueLength * sizeof(WCHAR));
                localBuffer[entry->ValueLength] = L'\0';
                valueString.Buffer = localBuffer;
                valueString.Length = entry->ValueLength * sizeof(WCHAR);
                valueString.MaximumLength = (entry->ValueLength + 1) * sizeof(WCHAR);

                status = ShadowStrikeAddProcessExclusion(
                    &valueString,
                    entry->Flags | (UINT8)ShadowStrikeExclusionFlagSystem
                );
                if (NT_SUCCESS(status)) {
                    accepted++;
                } else {
                    rejected++;
                }
                break;
            }

            case SHADOWSTRIKE_WL_TYPE_HASH:
            case SHADOWSTRIKE_WL_TYPE_CERTIFICATE:
            {
                //
                // Hash and certificate whitelisting require IOCMatcher integration
                // with a "clean" verdict. Use IomLoadIOC with severity=Safe.
                //
                PIOM_MATCHER matcher = BeGetIocMatcher();
                if (matcher != NULL) {
                    IOM_IOC_INPUT iocInput;
                    ULONG hashLen;

                    RtlZeroMemory(&iocInput, sizeof(iocInput));

                    switch (entry->HashType) {
                        case 0: hashLen = 16; break;
                        case 1: hashLen = 20; break;
                        case 2: hashLen = 32; break;
                        default: hashLen = 0; break;
                    }

                    if (hashLen > 0) {
                        for (ULONG b = 0; b < hashLen; b++) {
                            UCHAR hi = (entry->Hash[b] >> 4) & 0x0F;
                            UCHAR lo = entry->Hash[b] & 0x0F;
                            iocInput.Value[b * 2]     = (CHAR)(hi < 10 ? '0' + hi : 'a' + hi - 10);
                            iocInput.Value[b * 2 + 1] = (CHAR)(lo < 10 ? '0' + lo : 'a' + lo - 10);
                        }
                        iocInput.ValueLength = hashLen * 2;

                        //
                        // Map hash type to proper IOC enum values
                        //
                        switch (entry->HashType) {
                            case 0: iocInput.Type = IomType_FileHash_MD5; break;
                            case 1: iocInput.Type = IomType_FileHash_SHA1; break;
                            case 2: iocInput.Type = IomType_FileHash_SHA256; break;
                            default: iocInput.Type = IomType_FileHash_SHA256; break;
                        }
                        iocInput.Severity = IomSeverity_Unknown;  // Safe/whitelisted
                        RtlStringCbCopyA(iocInput.Source, sizeof(iocInput.Source), "Whitelist");

                        status = IomLoadIOC(matcher, &iocInput);
                        if (NT_SUCCESS(status)) {
                            accepted++;
                        } else {
                            rejected++;
                        }
                    } else {
                        rejected++;
                    }
                } else {
                    rejected++;
                }
                break;
            }

            default:
                rejected++;
                break;
        }

        cursor += entryTotalSize;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] PushWhitelist: %u accepted, %u rejected\n",
               accepted, rejected);

    //
    // Audit trail: whitelist modifications reduce detection surface
    //
    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_WhitelistModified,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle behavioral rules push (FilterMessageType_UpdateBehavioralRules).
 *
 * Supports Add, Remove, Enable, and Disable operations on behavioral rules.
 * Add operations convert wire format to RE_RULE and call ReLoadRule().
 */
static NTSTATUS
MhpHandleUpdateBehavioralRules(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PRE_ENGINE engine;
    PSHADOWSTRIKE_PUSH_BEHAVIORAL_RULE ruleEntry;
    ULONG i;
    PUCHAR cursor;
    PUCHAR payloadEnd;
    ULONG entryTotalSize;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Variable-size entries (Add operations have trailing conditions/actions)
    //
    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize, 0,
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    engine = BeGetRuleEngine();
    if (engine == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] UpdateBehavioralRules: RuleEngine not available\n");
        MhpBuildPushReply(Header, STATUS_DEVICE_NOT_READY, 0, entryCount,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_DEVICE_NOT_READY;
    }

    cursor = (PUCHAR)entriesStart;
    payloadEnd = (PUCHAR)PayloadBuffer + PayloadSize;

    for (i = 0; i < entryCount; i++) {
        if (cursor + sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE) > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        ruleEntry = (PSHADOWSTRIKE_PUSH_BEHAVIORAL_RULE)cursor;

        //
        // Ensure null termination of RuleId
        //
        ruleEntry->RuleId[sizeof(ruleEntry->RuleId) - 1] = '\0';

        switch (ruleEntry->Operation) {
            case SHADOWSTRIKE_RULE_OP_ADD:
            {
                RE_RULE rule;
                ULONG condSize, actSize;

                //
                // Validate condition/action counts
                //
                if (ruleEntry->ConditionCount > RE_MAX_CONDITIONS ||
                    ruleEntry->ActionCount > RE_MAX_ACTIONS) {
                    //
                    // Cannot trust condition/action counts for cursor advancement.
                    // The multiplication (count * sizeof(struct)) would overflow,
                    // corrupting cursor position and enabling out-of-bounds reads.
                    // Reject all remaining entries and bail out safely.
                    //
                    rejected += (entryCount - i);
                    goto Done;
                }

                condSize = ruleEntry->ConditionCount * sizeof(RE_CONDITION);
                actSize = ruleEntry->ActionCount * sizeof(RE_ACTION);
                entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE) + condSize + actSize;

                if (cursor + entryTotalSize > payloadEnd) {
                    rejected += (entryCount - i);
                    goto Done;
                }

                //
                // Build RE_RULE from wire format
                //
                RtlZeroMemory(&rule, sizeof(rule));

                RtlCopyMemory(rule.RuleId, ruleEntry->RuleId,
                               min(sizeof(ruleEntry->RuleId), RE_MAX_RULE_ID_LEN));
                rule.RuleId[RE_MAX_RULE_ID_LEN] = '\0';

                ruleEntry->RuleName[sizeof(ruleEntry->RuleName) - 1] = '\0';
                RtlCopyMemory(rule.RuleName, ruleEntry->RuleName,
                               min(sizeof(ruleEntry->RuleName), RE_MAX_RULE_NAME_LEN));
                rule.RuleName[RE_MAX_RULE_NAME_LEN] = '\0';

                ruleEntry->Description[sizeof(ruleEntry->Description) - 1] = '\0';
                RtlCopyMemory(rule.Description, ruleEntry->Description,
                               min(sizeof(ruleEntry->Description), RE_MAX_DESCRIPTION_LEN));
                rule.Description[RE_MAX_DESCRIPTION_LEN] = '\0';

                rule.Priority = ruleEntry->Priority;
                rule.Enabled = TRUE;
                rule.StopProcessing = (BOOLEAN)ruleEntry->StopProcessing;
                rule.ConditionCount = ruleEntry->ConditionCount;
                rule.ActionCount = ruleEntry->ActionCount;

                //
                // Copy conditions and actions from variable data
                //
                if (ruleEntry->ConditionCount > 0) {
                    RtlCopyMemory(rule.Conditions,
                                   cursor + sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE),
                                   condSize);
                }
                if (ruleEntry->ActionCount > 0) {
                    RtlCopyMemory(rule.Actions,
                                   cursor + sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE) + condSize,
                                   actSize);
                }

                status = ReLoadRule(engine, &rule);
                if (NT_SUCCESS(status)) {
                    accepted++;
                } else {
                    rejected++;
                }

                cursor += entryTotalSize;
                continue;
            }

            case SHADOWSTRIKE_RULE_OP_REMOVE:
            {
                status = ReRemoveRule(engine, ruleEntry->RuleId);
                if (NT_SUCCESS(status)) {
                    accepted++;
                } else {
                    rejected++;
                }
                cursor += sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE);
                continue;
            }

            case SHADOWSTRIKE_RULE_OP_ENABLE:
            {
                status = ReEnableRule(engine, ruleEntry->RuleId, TRUE);
                if (NT_SUCCESS(status)) {
                    accepted++;
                } else {
                    rejected++;
                }
                cursor += sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE);
                continue;
            }

            case SHADOWSTRIKE_RULE_OP_DISABLE:
            {
                status = ReEnableRule(engine, ruleEntry->RuleId, FALSE);
                if (NT_SUCCESS(status)) {
                    accepted++;
                } else {
                    rejected++;
                }
                cursor += sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE);
                continue;
            }

            default:
                rejected++;
                cursor += sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE);
                continue;
        }
    }

Done:
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] UpdateBehavioralRules: %u accepted, %u rejected\n",
               accepted, rejected);

    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ThreatIntelPushed,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle network IoC push (FilterMessageType_PushNetworkIoC).
 *
 * Routes network threat indicators to the appropriate subsystem:
 * - IPv4/IPv6 → C2Detection + NetworkReputation
 * - Domain → C2Detection + DnsMonitor + NetworkReputation
 * - JA3 → C2Detection + SSLInspection
 * - URL → C2Detection
 */
static NTSTATUS
MhpHandlePushNetworkIoC(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PC2_DETECTOR c2Detector;
    PDNS_MONITOR dnsMonitor;
    PNR_MANAGER repManager;
    PSHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY entry;
    ULONG i;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize,
        sizeof(SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY),
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    c2Detector = NfFilterGetC2Detector();
    dnsMonitor = NfFilterGetDnsMonitor();
    repManager = NfFilterGetReputationManager();

    if (c2Detector == NULL && dnsMonitor == NULL && repManager == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] PushNetworkIoC: No network modules available\n");
        MhpBuildPushReply(Header, STATUS_DEVICE_NOT_READY, 0, entryCount,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_DEVICE_NOT_READY;
    }

    entry = (PSHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY)entriesStart;

    for (i = 0; i < entryCount; i++) {
        BOOLEAN entryAccepted = FALSE;

        //
        // Ensure null termination of string fields
        //
        entry->ThreatName[sizeof(entry->ThreatName) - 1] = '\0';
        entry->MalwareFamily[sizeof(entry->MalwareFamily) - 1] = '\0';

        switch (entry->Type) {
            case SHADOWSTRIKE_NET_IOC_IPV4:
            {
                //
                // Add to C2Detection
                //
                if (c2Detector != NULL) {
                    C2_IOC c2Ioc;
                    RtlZeroMemory(&c2Ioc, sizeof(c2Ioc));
                    c2Ioc.Type = IOCType_IP;
                    c2Ioc.Value.IP.Address.S_un.S_addr = entry->Value.IPv4;
                    c2Ioc.Value.IP.IsIPv6 = FALSE;
                    RtlCopyMemory(c2Ioc.MalwareFamily, entry->MalwareFamily,
                                   min(sizeof(entry->MalwareFamily), sizeof(c2Ioc.MalwareFamily) - 1));
                    KeQuerySystemTimePrecise(&c2Ioc.AddedTime);
                    c2Ioc.ExpirationTime = entry->Expiry;

                    status = C2AddIOC(c2Detector, &c2Ioc);
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }

                //
                // Add to NetworkReputation
                //
                if (repManager != NULL) {
                    status = NrAddIP(
                        repManager,
                        &entry->Value.IPv4,
                        FALSE,
                        (NR_REPUTATION)entry->Reputation,
                        (NR_CATEGORY)entry->Categories,
                        entry->Score,
                        entry->ThreatName[0] ? entry->ThreatName : NULL
                    );
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }
                break;
            }

            case SHADOWSTRIKE_NET_IOC_IPV6:
            {
                if (c2Detector != NULL) {
                    C2_IOC c2Ioc;
                    RtlZeroMemory(&c2Ioc, sizeof(c2Ioc));
                    c2Ioc.Type = IOCType_IP;
                    c2Ioc.Value.IP.IsIPv6 = TRUE;
                    RtlCopyMemory(&c2Ioc.Value.IP.Address6, entry->Value.IPv6, sizeof(IN6_ADDR));
                    RtlCopyMemory(c2Ioc.MalwareFamily, entry->MalwareFamily,
                                   min(sizeof(entry->MalwareFamily), sizeof(c2Ioc.MalwareFamily) - 1));
                    KeQuerySystemTimePrecise(&c2Ioc.AddedTime);
                    c2Ioc.ExpirationTime = entry->Expiry;

                    status = C2AddIOC(c2Detector, &c2Ioc);
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }

                if (repManager != NULL) {
                    status = NrAddIP(
                        repManager,
                        entry->Value.IPv6,
                        TRUE,
                        (NR_REPUTATION)entry->Reputation,
                        (NR_CATEGORY)entry->Categories,
                        entry->Score,
                        entry->ThreatName[0] ? entry->ThreatName : NULL
                    );
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }
                break;
            }

            case SHADOWSTRIKE_NET_IOC_DOMAIN:
            {
                //
                // Ensure domain is null-terminated
                //
                entry->Value.Domain[sizeof(entry->Value.Domain) - 1] = '\0';

                if (c2Detector != NULL) {
                    C2_IOC c2Ioc;
                    RtlZeroMemory(&c2Ioc, sizeof(c2Ioc));
                    c2Ioc.Type = IOCType_Domain;
                    RtlCopyMemory(c2Ioc.Value.Domain, entry->Value.Domain,
                                   sizeof(c2Ioc.Value.Domain) - 1);
                    c2Ioc.Value.Domain[sizeof(c2Ioc.Value.Domain) - 1] = '\0';
                    RtlCopyMemory(c2Ioc.MalwareFamily, entry->MalwareFamily,
                                   min(sizeof(entry->MalwareFamily), sizeof(c2Ioc.MalwareFamily) - 1));
                    KeQuerySystemTimePrecise(&c2Ioc.AddedTime);
                    c2Ioc.ExpirationTime = entry->Expiry;

                    status = C2AddIOC(c2Detector, &c2Ioc);
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }

                //
                // Set domain reputation
                //
                if (dnsMonitor != NULL) {
                    status = DnsSetDomainReputation(
                        dnsMonitor,
                        entry->Value.Domain,
                        (DNS_REPUTATION)entry->Reputation,
                        entry->Score
                    );
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }

                //
                // Add to NetworkReputation
                //
                if (repManager != NULL) {
                    status = NrAddDomain(
                        repManager,
                        entry->Value.Domain,
                        (NR_REPUTATION)entry->Reputation,
                        (NR_CATEGORY)entry->Categories,
                        entry->Score,
                        entry->ThreatName[0] ? entry->ThreatName : NULL
                    );
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }
                break;
            }

            case SHADOWSTRIKE_NET_IOC_JA3:
            {
                if (c2Detector != NULL) {
                    status = C2AddKnownJA3(
                        c2Detector,
                        entry->Value.JA3Hash,
                        entry->MalwareFamily[0] ? entry->MalwareFamily : NULL
                    );
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }

                //
                // Route to SSLInspection bad-JA3 list for TLS handshake matching
                //
                {
                    PSSL_INSPECTOR sslInspector = NfFilterGetSslInspector();
                    if (sslInspector != NULL) {
                        status = SslAddBadJA3(
                            sslInspector,
                            entry->Value.JA3Hash,
                            entry->MalwareFamily[0] ? entry->MalwareFamily : NULL
                        );
                        if (NT_SUCCESS(status)) {
                            entryAccepted = TRUE;
                        }
                    }
                }
                break;
            }

            case SHADOWSTRIKE_NET_IOC_URL:
            {
                entry->Value.URL[sizeof(entry->Value.URL) - 1] = '\0';

                if (c2Detector != NULL) {
                    C2_IOC c2Ioc;
                    RtlZeroMemory(&c2Ioc, sizeof(c2Ioc));
                    c2Ioc.Type = IOCType_URL;
                    RtlCopyMemory(c2Ioc.Value.URL, entry->Value.URL,
                                   sizeof(c2Ioc.Value.URL) - 1);
                    c2Ioc.Value.URL[sizeof(c2Ioc.Value.URL) - 1] = '\0';
                    RtlCopyMemory(c2Ioc.MalwareFamily, entry->MalwareFamily,
                                   min(sizeof(entry->MalwareFamily), sizeof(c2Ioc.MalwareFamily) - 1));
                    KeQuerySystemTimePrecise(&c2Ioc.AddedTime);
                    c2Ioc.ExpirationTime = entry->Expiry;

                    status = C2AddIOC(c2Detector, &c2Ioc);
                    if (NT_SUCCESS(status)) {
                        entryAccepted = TRUE;
                    }
                }
                break;
            }

            default:
                break;
        }

        if (entryAccepted) {
            accepted++;
        } else {
            rejected++;
        }

        entry++;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] PushNetworkIoC: %u accepted, %u rejected\n",
               accepted, rejected);

    //
    // Audit trail: network IOC updates affect network threat detection
    //
    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ThreatIntelPushed,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle exclusion update (FilterMessageType_ExclusionUpdate).
 *
 * Add, remove, or clear exclusions in the ExclusionManager.
 * Supports path, extension, process name, and PID exclusion types.
 */
static NTSTATUS
MhpHandleExclusionUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PUSH_BATCH_HEADER batchHeader;
    PVOID entriesStart;
    ULONG entryCount;
    ULONG accepted = 0;
    ULONG rejected = 0;
    PSHADOWSTRIKE_PUSH_EXCLUSION_ENTRY entry;
    ULONG i;
    PUCHAR cursor;
    PUCHAR payloadEnd;
    ULONG entryTotalSize;
    UNICODE_STRING valueString;
    WCHAR localBuffer[260];

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Variable-size entries (trailing WCHAR value)
    //
    status = MhpValidateBatchHeader(
        PayloadBuffer, PayloadSize, 0,
        &batchHeader, &entriesStart, &entryCount
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (entryCount == 0) {
        MhpBuildPushReply(Header, STATUS_SUCCESS, 0, 0,
                         OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
        return STATUS_SUCCESS;
    }

    cursor = (PUCHAR)entriesStart;
    payloadEnd = (PUCHAR)PayloadBuffer + PayloadSize;

    for (i = 0; i < entryCount; i++) {
        if (cursor + sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY) > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        entry = (PSHADOWSTRIKE_PUSH_EXCLUSION_ENTRY)cursor;

        //
        // Handle clear operation (no value needed)
        //
        if (entry->Operation == SHADOWSTRIKE_EXCL_OP_CLEAR) {
            if (entry->ExclusionType < ShadowStrikeExclusionTypeMax) {
                ShadowStrikeClearExclusions((SHADOWSTRIKE_EXCLUSION_TYPE)entry->ExclusionType);
                accepted++;
            } else {
                rejected++;
            }
            cursor += sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY);
            continue;
        }

        //
        // For PID exclusions, value is UINT64 (no WCHAR string)
        //
        if (entry->ExclusionType == (UINT8)ShadowStrikeExclusionProcessId) {
            entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY) + sizeof(UINT64);
            if (cursor + entryTotalSize > payloadEnd) {
                rejected += (entryCount - i);
                break;
            }

            UINT64 pidValue = *(PUINT64)((PUCHAR)entry + sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY));

            if (entry->Operation == SHADOWSTRIKE_EXCL_OP_ADD) {
                status = ShadowStrikeAddPidExclusion((HANDLE)(ULONG_PTR)pidValue, entry->TTLSeconds);
            } else {
                BOOLEAN removed = ShadowStrikeRemovePidExclusion((HANDLE)(ULONG_PTR)pidValue);
                status = removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            }

            if (NT_SUCCESS(status)) {
                accepted++;
            } else {
                rejected++;
            }

            cursor += entryTotalSize;
            continue;
        }

        //
        // String-based exclusions (path, extension, process name)
        //
        if (entry->ValueLength == 0 || entry->ValueLength > 259) {
            rejected++;
            entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY) + entry->ValueLength * sizeof(WCHAR);
            if (cursor + entryTotalSize <= payloadEnd) {
                cursor += entryTotalSize;
            } else {
                rejected += (entryCount - i - 1);
                break;
            }
            continue;
        }

        entryTotalSize = sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY) + entry->ValueLength * sizeof(WCHAR);
        if (cursor + entryTotalSize > payloadEnd) {
            rejected += (entryCount - i);
            break;
        }

        //
        // Build UNICODE_STRING from value data
        //
        PWCHAR valueData = (PWCHAR)((PUCHAR)entry + sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY));
        RtlCopyMemory(localBuffer, valueData, entry->ValueLength * sizeof(WCHAR));
        localBuffer[entry->ValueLength] = L'\0';
        valueString.Buffer = localBuffer;
        valueString.Length = entry->ValueLength * sizeof(WCHAR);
        valueString.MaximumLength = (entry->ValueLength + 1) * sizeof(WCHAR);

        switch (entry->ExclusionType) {
            case (UINT8)ShadowStrikeExclusionPath:
                if (entry->Operation == SHADOWSTRIKE_EXCL_OP_ADD) {
                    status = ShadowStrikeAddPathExclusion(&valueString, entry->Flags, entry->TTLSeconds);
                } else {
                    BOOLEAN removed = ShadowStrikeRemovePathExclusion(&valueString);
                    status = removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                }
                break;

            case (UINT8)ShadowStrikeExclusionExtension:
                if (entry->Operation == SHADOWSTRIKE_EXCL_OP_ADD) {
                    status = ShadowStrikeAddExtensionExclusion(&valueString, entry->Flags);
                } else {
                    BOOLEAN removed = ShadowStrikeRemoveExtensionExclusion(&valueString);
                    status = removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                }
                break;

            case (UINT8)ShadowStrikeExclusionProcessName:
                if (entry->Operation == SHADOWSTRIKE_EXCL_OP_ADD) {
                    status = ShadowStrikeAddProcessExclusion(&valueString, entry->Flags);
                } else {
                    BOOLEAN removed = ShadowStrikeRemoveProcessExclusion(&valueString);
                    status = removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                }
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }

        if (NT_SUCCESS(status)) {
            accepted++;
        } else {
            rejected++;
        }

        cursor += entryTotalSize;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] ExclusionUpdate: %u accepted, %u rejected\n",
               accepted, rejected);

    //
    // Audit trail: exclusion modifications directly affect detection coverage
    //
    if (accepted > 0) {
        UINT32 callerPid = (ClientContext != NULL && ClientContext->ClientProcessId != NULL) ?
                           (UINT32)(ULONG_PTR)ClientContext->ClientProcessId : 0;
        BeEngineSubmitEvent(
            BehaviorEvent_ExclusionModified,
            BehaviorCategory_ManagementAudit,
            callerPid,
            NULL, 0, 0, FALSE, NULL
        );
    }

    MhpBuildPushReply(Header, STATUS_SUCCESS, accepted, rejected,
                     OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);

    return STATUS_SUCCESS;
}
