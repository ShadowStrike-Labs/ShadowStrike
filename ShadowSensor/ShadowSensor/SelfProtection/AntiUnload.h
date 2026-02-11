/**
 * ============================================================================
 * ShadowStrike NGAV - ANTI-UNLOAD PROTECTION
 * ============================================================================
 *
 * @file AntiUnload.h
 * @brief Enterprise-grade driver unload prevention and tamper resistance.
 *
 * Architecture:
 * - DriverObject->DriverUnload is nulled to block NtUnloadDriver
 * - ObRegisterCallbacks strips dangerous access from protected process handles
 * - Protected processes identified by registered PID (not by name)
 * - EX_RUNDOWN_REF ensures OB callbacks complete before shutdown
 * - EX_PUSH_LOCK synchronizes level transitions and callback registration
 * - Event history with deep-copy retrieval (no dangling pointers)
 *
 * Protection Levels:
 * - AuLevel_None:   No protection active
 * - AuLevel_Basic:  DriverUnload nulled (blocks NtUnloadDriver)
 * - AuLevel_Full:   + OB callbacks strip dangerous handle access
 *
 * Thread Safety:
 * - Level/callback changes: EX_PUSH_LOCK (PASSIVE_LEVEL)
 * - Event list: KSPIN_LOCK (≤ DISPATCH_LEVEL)
 * - OB callback lifetime: EX_RUNDOWN_REF
 * - Protected PID table: KSPIN_LOCK (≤ DISPATCH_LEVEL)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define AU_POOL_TAG         'LNUA'
#define AU_POOL_TAG_EVENT   'eAUA'
#define AU_POOL_TAG_PID     'pAUA'

// ============================================================================
// CONSTANTS
// ============================================================================

/** @brief Maximum events retained in history ring. */
#define AU_MAX_EVENTS       256

/** @brief Maximum simultaneously protected PIDs. */
#define AU_MAX_PROTECTED_PIDS 32

/** @brief Process image name max length (PsGetProcessImageFileName returns ≤ 15). */
#define AU_PROCESS_NAME_LEN 16

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Protection levels.
 *
 * Only two real levels: Basic (DriverUnload = NULL) and Full (+ OB callbacks).
 * No unimplemented levels — every value has concrete behavior.
 */
typedef enum _AU_PROTECTION_LEVEL {
    AuLevel_None  = 0,  /**< No protection active. */
    AuLevel_Basic = 1,  /**< DriverUnload nulled. */
    AuLevel_Full  = 2,  /**< + OB callbacks strip dangerous handle access. */
} AU_PROTECTION_LEVEL;

typedef enum _AU_UNLOAD_ATTEMPT {
    AuAttempt_None = 0,
    AuAttempt_ProcessTerminate,   /**< PROCESS_TERMINATE on protected process */
    AuAttempt_ProcessInject,      /**< PROCESS_VM_WRITE/CREATE_THREAD on protected process */
    AuAttempt_ThreadTerminate,    /**< THREAD_TERMINATE on protected thread */
    AuAttempt_ThreadInject,       /**< THREAD_SET_CONTEXT on protected thread */
} AU_UNLOAD_ATTEMPT;

// ============================================================================
// EVENT STRUCTURE (flat, no embedded pointers)
// ============================================================================

/**
 * @brief Unload attempt event.
 *
 * Flat structure with no pointers — safe for deep copy and for
 * return from AuGetEvents. ProcessName uses fixed CHAR buffer
 * from PsGetProcessImageFileName (max 15 chars + NUL).
 */
typedef struct _AU_UNLOAD_EVENT {
    AU_UNLOAD_ATTEMPT Type;
    HANDLE            CallerProcessId;
    HANDLE            TargetProcessId;
    CHAR              CallerImageName[AU_PROCESS_NAME_LEN];
    LARGE_INTEGER     Timestamp;
    BOOLEAN           WasBlocked;

    LIST_ENTRY        ListEntry; /**< Internal — not valid after AuGetEvents copy. */
} AU_UNLOAD_EVENT, *PAU_UNLOAD_EVENT;

/**
 * @brief Callback invoked on unload attempt detection.
 *
 * Called at PASSIVE_LEVEL or APC_LEVEL (from OB callback context).
 * Must not block for extended periods. Must not fault.
 *
 * @param AttemptType     What kind of attempt was detected.
 * @param CallerProcessId PID of the process that triggered the attempt.
 * @param Context         Opaque context from AuRegisterCallback.
 * @return Ignored (reserved for future use).
 */
typedef BOOLEAN (*AU_UNLOAD_CALLBACK)(
    _In_ AU_UNLOAD_ATTEMPT AttemptType,
    _In_ HANDLE CallerProcessId,
    _In_opt_ PVOID Context
);

// ============================================================================
// PROTECTOR STRUCTURE
// ============================================================================

/**
 * @brief Anti-unload protector state.
 *
 * Allocated from NonPagedPoolNx in AuInitialize, freed in AuShutdown.
 *
 * Synchronization:
 * - ConfigLock (EX_PUSH_LOCK): protects Level, UserCallback, CallbackContext,
 *   ObCallbackHandle, OriginalUnload. Acquired exclusive for writes,
 *   shared for reads. Requires KeEnterCriticalRegion.
 * - EventLock (KSPIN_LOCK): protects EventList/EventCount.
 * - PidLock (KSPIN_LOCK): protects ProtectedPids/ProtectedPidCount.
 * - RundownRef (EX_RUNDOWN_REF): acquired in OB callbacks, waited on in AuShutdown.
 *   Ensures no in-flight callbacks when protector is freed.
 *
 * Lock ordering: ConfigLock → PidLock → EventLock
 */
typedef struct _AU_PROTECTOR {
    /** @brief TRUE after AuInitialize succeeds. */
    BOOLEAN Initialized;

    //
    // Synchronization
    //
    EX_PUSH_LOCK    ConfigLock;
    EX_RUNDOWN_REF  RundownRef;

    //
    // Driver state
    //
    PDRIVER_OBJECT  ProtectedDriver;
    PDRIVER_UNLOAD  OriginalUnload;

    //
    // Protection level (read under ConfigLock shared or interlocked)
    //
    volatile LONG   Level;

    //
    // OB callback handle (single handle covers process + thread)
    //
    PVOID           ObCallbackHandle;

    //
    // OB registration structs (per-instance, not global)
    //
    OB_CALLBACK_REGISTRATION    ObRegistration;
    OB_OPERATION_REGISTRATION   ObOperations[2];
    UNICODE_STRING              ObAltitude;

    //
    // User notification callback
    //
    AU_UNLOAD_CALLBACK  UserCallback;
    PVOID               CallbackContext;

    //
    // Protected PID table (registered by user-mode service)
    //
    KSPIN_LOCK  PidLock;
    HANDLE      ProtectedPids[AU_MAX_PROTECTED_PIDS];
    ULONG       ProtectedPidCount;

    //
    // Event history
    //
    LIST_ENTRY  EventList;
    KSPIN_LOCK  EventLock;
    ULONG       EventCount;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalAttempts;
        volatile LONG64 AttemptsBlocked;
        LARGE_INTEGER   StartTime;
    } Stats;

} AU_PROTECTOR, *PAU_PROTECTOR;

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize anti-unload protection.
 *
 * Allocates AU_PROTECTOR, nulls DriverObject->DriverUnload,
 * takes a reference on DriverObject.
 * Default level is AuLevel_Basic.
 *
 * @param DriverObject  The driver to protect (referenced).
 * @param Protector     [out] Receives allocated protector.
 * @return STATUS_SUCCESS or allocation failure.
 * @irql PASSIVE_LEVEL
 */
NTSTATUS AuInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _Out_ PAU_PROTECTOR* Protector
    );

/**
 * @brief Shutdown anti-unload protection.
 *
 * Steps:
 * 1. Mark not initialized (prevents new OB callback work).
 * 2. Unregister OB callbacks.
 * 3. ExWaitForRundownProtectionRelease (blocks until in-flight callbacks finish).
 * 4. Free event list.
 * 5. ObDereferenceObject(DriverObject).
 * 6. Restore DriverUnload (if caller wants controlled unload).
 * 7. Free protector.
 *
 * @param Protector  Protector to destroy. NULL-safe.
 * @irql PASSIVE_LEVEL
 */
VOID AuShutdown(
    _Inout_ PAU_PROTECTOR Protector
    );

/**
 * @brief Set protection level.
 *
 * Transitions between levels. Upgrading to AuLevel_Full registers
 * OB callbacks. Downgrading from Full unregisters them.
 * Serialized by ConfigLock.
 *
 * @param Protector  Protector handle.
 * @param Level      New level (AuLevel_None..AuLevel_Full).
 * @return STATUS_SUCCESS on success.
 * @irql PASSIVE_LEVEL
 */
NTSTATUS AuSetLevel(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_PROTECTION_LEVEL Level
    );

/**
 * @brief Register notification callback.
 *
 * Serialized by ConfigLock. Only one callback at a time.
 *
 * @param Protector  Protector handle.
 * @param Callback   Function to call on unload attempts. Must not fault.
 * @param Context    Opaque context passed to callback.
 * @irql PASSIVE_LEVEL
 */
NTSTATUS AuRegisterCallback(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_UNLOAD_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Register a PID as protected.
 *
 * OB callbacks will strip dangerous access from handles targeting
 * this PID's process/threads. Use this from a secured IOCTL when
 * the user-mode service registers itself.
 *
 * @param Protector  Protector handle.
 * @param ProcessId  PID to protect.
 * @return STATUS_SUCCESS, STATUS_INSUFFICIENT_RESOURCES if table full,
 *         STATUS_DUPLICATE_OBJECTID if already registered.
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS AuProtectProcess(
    _In_ PAU_PROTECTOR Protector,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Unregister a protected PID.
 *
 * @param Protector  Protector handle.
 * @param ProcessId  PID to unprotect.
 * @irql <= DISPATCH_LEVEL
 */
VOID AuUnprotectProcess(
    _In_ PAU_PROTECTOR Protector,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Get recent unload attempt events (deep copy).
 *
 * Copies up to Max events into the caller-provided buffer.
 * Events are ordered newest-first. The returned events are
 * independent copies — no lifetime dependency on the protector.
 *
 * @param Protector  Protector handle.
 * @param Events     Caller-allocated array of AU_UNLOAD_EVENT.
 * @param Max        Size of Events array.
 * @param Count      [out] Number of events actually copied.
 * @return STATUS_SUCCESS.
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS AuGetEvents(
    _In_ PAU_PROTECTOR Protector,
    _Out_writes_to_(Max, *Count) PAU_UNLOAD_EVENT Events,
    _In_ ULONG Max,
    _Out_ PULONG Count
    );

#ifdef __cplusplus
}
#endif
