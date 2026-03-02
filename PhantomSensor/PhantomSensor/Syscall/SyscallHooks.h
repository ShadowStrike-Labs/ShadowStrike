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
 * ShadowStrike NGAV - SYSCALL INTERCEPTION FRAMEWORK
 * ============================================================================
 *
 * @file SyscallHooks.h
 * @brief Enterprise-grade syscall hook registration and dispatch framework.
 *
 * This module provides the central mechanism layer for syscall interception:
 * - Hook registration/deregistration by syscall number
 * - Pre-call and post-call callback dispatch
 * - Thread-safe hook lifecycle with reference-counted quiescence
 * - Safe shutdown that drains all active callbacks before teardown
 * - Hash-based O(1) hook lookup supporting the full syscall number space
 * - Lookaside-pooled hook allocations for hot-path performance
 * - Rate limiting to prevent callback storms
 * - Comprehensive telemetry and statistics
 *
 * Architectural Role:
 * - SyscallHooks owns the MECHANISM (register, dispatch, lifecycle)
 * - SyscallMonitor owns the POLICY (what to monitor, analysis, decisions)
 * - DirectSyscallDetector, CallstackAnalyzer, HeavensGateDetector,
 *   NtdllIntegrity are ANALYSIS ENGINES plugged into callbacks
 *
 * Thread Safety:
 * - All public APIs are safe to call concurrently
 * - Hook dispatch uses EX_PUSH_LOCK (shared for reads, exclusive for writes)
 * - Hook enable/disable uses interlocked operations (lock-free on hot path)
 * - Shutdown drains active references before freeing any memory
 *
 * IRQL Contract:
 * - All public APIs require IRQL <= APC_LEVEL (PASSIVE_LEVEL preferred)
 * - Callbacks are invoked at PASSIVE_LEVEL
 * - Internal fast-path lookup is safe up to APC_LEVEL
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_SYSCALL_HOOKS_H_
#define _SHADOWSTRIKE_SYSCALL_HOOKS_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

// ============================================================================
// POOL TAGS & CONSTANTS
// ============================================================================

/** @brief Pool tag for SyscallHooks framework: 'ShHk' (little-endian) */
#define SH_POOL_TAG                         'kHhS'

/** @brief Pool tag for hook entry allocations */
#define SH_HOOK_TAG                         'oHhS'

/** @brief Pool tag for hash bucket allocations */
#define SH_HASH_TAG                         'aHhS'

/**
 * @brief Maximum syscall number supported.
 * Windows x64 syscall numbers can reach ~0x200+ depending on build.
 * We cap at 0x1000 to match SyscallMonitor.h and cover future growth.
 */
#define SH_MAX_SYSCALL_NUMBER               0x1000

/**
 * @brief Hash table bucket count for hook lookup.
 * Must be power of 2. 256 buckets gives ~4 entries/bucket at full load.
 */
#define SH_HASH_BUCKET_COUNT                256

/**
 * @brief Maximum number of hooks that can be registered simultaneously.
 * Bounded to prevent resource exhaustion by misconfigured callers.
 */
#define SH_MAX_REGISTERED_HOOKS             512

/** @brief Lookaside list depth for hook entry allocations */
#define SH_HOOK_LOOKASIDE_DEPTH             64

/** @brief Maximum concurrent callbacks before rate limiting kicks in */
#define SH_MAX_CONCURRENT_CALLBACKS         1024

/** @brief Framework magic for pointer validation */
#define SH_FRAMEWORK_MAGIC                  0x53484B46  /* 'SHKF' */

/** @brief Hook entry magic for pointer validation */
#define SH_HOOK_MAGIC                       0x53484B48  /* 'SHKH' */

/** @brief Maximum syscall arguments stored in context */
#define SH_MAX_ARGUMENTS                    8

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Result of a hook callback invocation.
 */
typedef enum _SH_HOOK_RESULT {
    /** Allow the syscall to proceed normally */
    ShResult_Allow      = 0,
    /** Block the syscall (return STATUS_ACCESS_DENIED to caller) */
    ShResult_Block      = 1,
    /** Log only — allow but flag for telemetry */
    ShResult_Log        = 2,
} SH_HOOK_RESULT;

// ============================================================================
// CALLBACK CONTEXT
// ============================================================================

/**
 * @brief Context passed to hook callbacks during syscall interception.
 *
 * Populated by the framework before invoking callbacks.
 * The ReturnValue pointer is only valid during post-call callbacks
 * (when IsPreCall == FALSE). Dereferencing it during pre-call is undefined.
 */
typedef struct _SH_SYSCALL_CONTEXT {
    /** Calling process ID */
    HANDLE ProcessId;

    /** Calling thread ID */
    HANDLE ThreadId;

    /** Syscall number being intercepted */
    ULONG SyscallNumber;

    /** Padding for alignment */
    ULONG Reserved0;

    /** Syscall arguments (first SH_MAX_ARGUMENTS) */
    ULONG64 Arguments[SH_MAX_ARGUMENTS];

    /** Number of valid arguments in the Arguments array */
    ULONG ArgumentCount;

    /** TRUE if this is a pre-call invocation, FALSE for post-call */
    BOOLEAN IsPreCall;

    /** Padding */
    UCHAR Reserved1[3];

    /** User-mode return address of the syscall caller (informational only — NOT dereferenced) */
    ULONG64 CallerReturnAddress;

    /**
     * @brief Pointer to the syscall return value (post-call only).
     *
     * Valid ONLY when IsPreCall == FALSE. During pre-call, this is NULL.
     * Callbacks MUST NOT dereference this pointer during pre-call.
     * On post-call, points to the NTSTATUS result of the original syscall.
     */
    _When_(IsPreCall == FALSE, _Notnull_)
    _When_(IsPreCall == TRUE, _Null_)
    NTSTATUS *ReturnValue;

} SH_SYSCALL_CONTEXT, *PSH_SYSCALL_CONTEXT;

/**
 * @brief Hook callback function signature.
 *
 * @param Context   Syscall context describing the intercepted call.
 * @param Cookie    Opaque caller-supplied context from hook registration.
 * @return SH_HOOK_RESULT indicating the disposition of the syscall.
 *
 * IRQL: Called at PASSIVE_LEVEL.
 * Callbacks MUST NOT raise IRQL, acquire spinlocks, or block indefinitely.
 * Callbacks MUST complete within a bounded time (recommended <1ms).
 */
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
SH_HOOK_RESULT
(*SH_HOOK_CALLBACK)(
    _In_ PSH_SYSCALL_CONTEXT Context,
    _In_opt_ PVOID Cookie
    );

// ============================================================================
// OPAQUE HANDLES
// ============================================================================

/**
 * @brief Opaque handle to the syscall hooks framework.
 * Allocated by ShInitialize, freed by ShShutdown.
 */
DECLARE_HANDLE(SH_FRAMEWORK_HANDLE);

/**
 * @brief Opaque handle to a registered hook entry.
 * Returned by ShRegisterHook, invalidated by ShUnregisterHook.
 */
DECLARE_HANDLE(SH_HOOK_HANDLE);

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

/**
 * @brief Initialize the syscall hooks framework.
 *
 * Allocates the framework structure, hash table, lookaside lists,
 * and synchronization primitives. Must be called once at driver init.
 *
 * @param[out] Framework    Receives the framework handle on success.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if Framework is NULL.
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShInitialize(
    _Out_ SH_FRAMEWORK_HANDLE *Framework
    );

/**
 * @brief Shut down the syscall hooks framework.
 *
 * Signals shutdown, waits for all active callback invocations to drain,
 * removes and frees all registered hooks, then frees the framework.
 * After this call, the framework handle is invalid.
 *
 * @param[in] Framework     Framework handle from ShInitialize.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShShutdown(
    _In_ _Post_invalid_ SH_FRAMEWORK_HANDLE Framework
    );

// ============================================================================
// PUBLIC API — HOOK REGISTRATION
// ============================================================================

/**
 * @brief Register a hook for a specific syscall number.
 *
 * At least one of PreCallback or PostCallback must be non-NULL.
 * The hook is created in the disabled state. Call ShEnableHook to activate.
 *
 * @param[in]  Framework     Framework handle.
 * @param[in]  SyscallNumber Syscall number to hook (must be < SH_MAX_SYSCALL_NUMBER).
 * @param[in]  PreCallback   Optional pre-call callback.
 * @param[in]  PostCallback  Optional post-call callback.
 * @param[in]  Cookie        Optional opaque context passed to callbacks.
 * @param[out] Hook          Receives the hook handle on success.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if inputs are invalid.
 * @return STATUS_QUOTA_EXCEEDED if SH_MAX_REGISTERED_HOOKS reached.
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShRegisterHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ ULONG SyscallNumber,
    _In_opt_ SH_HOOK_CALLBACK PreCallback,
    _In_opt_ SH_HOOK_CALLBACK PostCallback,
    _In_opt_ PVOID Cookie,
    _Out_ SH_HOOK_HANDLE *Hook
    );

/**
 * @brief Unregister a previously registered hook.
 *
 * Marks the hook for removal, waits for any active callbacks on this hook
 * to complete (reference drain), then frees the hook entry.
 * After this call, the hook handle is invalid.
 *
 * @param[in] Framework     Framework handle.
 * @param[in] Hook          Hook handle from ShRegisterHook.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if inputs are invalid.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShUnregisterHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ _Post_invalid_ SH_HOOK_HANDLE Hook
    );

// ============================================================================
// PUBLIC API — HOOK CONTROL
// ============================================================================

/**
 * @brief Enable a registered hook (lock-free, interlocked).
 *
 * @param[in] Framework     Framework handle.
 * @param[in] Hook          Hook handle.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if inputs are invalid.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShEnableHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ SH_HOOK_HANDLE Hook
    );

/**
 * @brief Disable a registered hook (lock-free, interlocked).
 *
 * @param[in] Framework     Framework handle.
 * @param[in] Hook          Hook handle.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if inputs are invalid.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShDisableHook(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ SH_HOOK_HANDLE Hook
    );

// ============================================================================
// PUBLIC API — DISPATCH
// ============================================================================

/**
 * @brief Dispatch callbacks for a syscall interception.
 *
 * This is the HOT PATH. Looks up all hooks registered for the given
 * syscall number and invokes their callbacks. If any callback returns
 * ShResult_Block, dispatch stops and the result is Block.
 *
 * @param[in]  Framework    Framework handle.
 * @param[in]  Context      Syscall context describing the intercepted call.
 * @param[out] Result       Receives the aggregated hook result.
 * @return STATUS_SUCCESS if dispatch completed.
 * @return STATUS_INVALID_PARAMETER if inputs are invalid.
 * @return STATUS_DEVICE_NOT_READY if framework is shutting down.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShDispatchSyscall(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _In_ PSH_SYSCALL_CONTEXT Context,
    _Out_ SH_HOOK_RESULT *Result
    );

// ============================================================================
// PUBLIC API — STATISTICS
// ============================================================================

/**
 * @brief Syscall hooks framework statistics (read-only snapshot).
 */
typedef struct _SH_STATISTICS {
    /** Total syscall dispatches processed */
    LONG64 TotalDispatches;
    /** Total individual callback invocations */
    LONG64 TotalCallbackInvocations;
    /** Total syscalls blocked by callbacks */
    LONG64 TotalBlocked;
    /** Total syscalls logged by callbacks */
    LONG64 TotalLogged;
    /** Total dispatches dropped due to rate limiting */
    LONG64 TotalRateLimited;
    /** Current number of registered hooks */
    LONG RegisteredHookCount;
    /** Current number of enabled hooks */
    LONG EnabledHookCount;
    /** Peak concurrent active dispatches */
    LONG PeakConcurrentDispatches;
    /** Framework uptime start */
    LARGE_INTEGER StartTime;
} SH_STATISTICS, *PSH_STATISTICS;

/**
 * @brief Get a snapshot of framework statistics.
 *
 * @param[in]  Framework    Framework handle.
 * @param[out] Stats        Receives the statistics snapshot.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if inputs are invalid.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShGetStatistics(
    _In_ SH_FRAMEWORK_HANDLE Framework,
    _Out_ PSH_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif

#endif /* _SHADOWSTRIKE_SYSCALL_HOOKS_H_ */
