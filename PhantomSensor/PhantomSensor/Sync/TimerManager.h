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
    Module: TimerManager.h

    Purpose: Centralized timer management for periodic tasks,
             timeouts, and scheduled work in the kernel driver.

    Architecture:
    - High-resolution timer support via KeSetCoalescableTimer
    - Timer wheel for efficient deadline-miss detection
    - One-shot and periodic timers with reference counting
    - Timer coalescing for power efficiency
    - WorkItem support for PASSIVE_LEVEL callbacks via IoQueueWorkItem

    Copyright (c) ShadowStrike Team
--*/

#ifndef _SHADOWSTRIKE_TIMER_MANAGER_H_
#define _SHADOWSTRIKE_TIMER_MANAGER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define TM_POOL_TAG_TIMER       'RTMT'  // Timer Manager - Timer
#define TM_POOL_TAG_WHEEL       'WHTM'  // Timer Manager - Wheel
#define TM_POOL_TAG_CONTEXT     'XCTM'  // Timer Manager - Context

//=============================================================================
// Configuration Constants
//=============================================================================

// Timer limits
#define TM_MAX_TIMERS               1024
#define TM_MIN_PERIOD_MS            1
#define TM_MAX_PERIOD_MS            (24 * 60 * 60 * 1000)  // 24 hours
#define TM_DEFAULT_TOLERANCE_MS     50      // Default timer tolerance

// Timer wheel configuration
#define TM_WHEEL_SIZE               256     // Slots in timer wheel (power of 2)
#define TM_WHEEL_MASK               (TM_WHEEL_SIZE - 1)
#define TM_WHEEL_RESOLUTION_MS      10      // Resolution per slot
#define TM_WHEEL_SPAN_MS            (TM_WHEEL_SIZE * TM_WHEEL_RESOLUTION_MS)

// Coalescing groups
#define TM_COALESCE_GROUP_TELEMETRY     1
#define TM_COALESCE_GROUP_MAINTENANCE   2
#define TM_COALESCE_GROUP_STATISTICS    3

// Name field max length (including NUL)
#define TM_TIMER_NAME_MAX           32

// Shutdown spin limit to avoid livelock
#define TM_SHUTDOWN_SPIN_LIMIT      5000

//=============================================================================
// Timer Types
//=============================================================================

typedef enum _TM_TIMER_TYPE {
    TmTimerType_OneShot = 0,            // Fire once
    TmTimerType_Periodic,               // Fire repeatedly
    TmTimerType_Deadline,               // Must fire by deadline
    TmTimerType_Idle                    // Fire during idle periods
} TM_TIMER_TYPE;

//=============================================================================
// Timer State
//=============================================================================

typedef enum _TM_TIMER_STATE {
    TmTimerState_Free = 0,
    TmTimerState_Created,
    TmTimerState_Active,
    TmTimerState_Firing,
    TmTimerState_Cancelled,
    TmTimerState_Expired
} TM_TIMER_STATE;

//=============================================================================
// Timer Flags
//=============================================================================

typedef enum _TM_TIMER_FLAGS {
    TmFlag_None                 = 0x00000000,
    TmFlag_HighResolution       = 0x00000001,   // High-res timer (no coalescing)
    TmFlag_Coalescable          = 0x00000002,   // Can be coalesced
    TmFlag_NoWake               = 0x00000004,   // Don't wake from sleep
    TmFlag_DpcCallback          = 0x00000008,   // Callback runs at DISPATCH
    TmFlag_WorkItemCallback     = 0x00000010,   // Callback queued as work item (PASSIVE)
    TmFlag_AutoDelete           = 0x00000020,   // Delete after one-shot fires
    TmFlag_Synchronized         = 0x00000040,   // Manual start (don't auto-start on create)
} TM_TIMER_FLAGS;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*TM_TIMER_CALLBACK)(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Timer Object (public portion, embedded in internal struct)
//=============================================================================

typedef struct _TM_TIMER {
    //
    // Kernel timer
    //
    KTIMER KernelTimer;
    KDPC TimerDpc;

    //
    // Timer identification
    //
    ULONG TimerId;
    CHAR Name[TM_TIMER_NAME_MAX];
    TM_TIMER_TYPE Type;
    TM_TIMER_FLAGS Flags;
    volatile LONG State;    // TM_TIMER_STATE via InterlockedCompareExchange

    //
    // Timing parameters
    //
    LARGE_INTEGER DueTime;              // When to fire (relative, negative 100ns)
    LARGE_INTEGER Period;               // Period for periodic timers (negative 100ns)
    ULONG ToleranceMs;                  // Tolerance for coalescing

    //
    // Callback
    //
    TM_TIMER_CALLBACK Callback;
    PVOID Context;
    ULONG ContextSize;                  // >0 means we own Context (copied)

    //
    // Coalescing
    //
    ULONG CoalesceGroup;

    //
    // Statistics
    //
    volatile LONG64 FireCount;
    LARGE_INTEGER LastFireTime;
    LARGE_INTEGER NextFireTime;
    LARGE_INTEGER CreationTime;

    //
    // Cancellation support
    //
    KEVENT CancelEvent;
    volatile LONG CancelRequested;      // LONG for Interlocked ops

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;               // Link in TM_MANAGER::TimerList
    LIST_ENTRY WheelEntry;              // Link in TM_WHEEL_SLOT::TimerList

} TM_TIMER, *PTM_TIMER;

//=============================================================================
// Timer Wheel Slot
//=============================================================================

typedef struct _TM_WHEEL_SLOT {
    LIST_ENTRY TimerList;
    KSPIN_LOCK Lock;
    volatile LONG TimerCount;
} TM_WHEEL_SLOT, *PTM_WHEEL_SLOT;

//=============================================================================
// Timer Manager
//=============================================================================

typedef struct _TM_MANAGER {
    //
    // Initialization state — volatile LONG for interlocked CAS
    //
    volatile LONG Initialized;          // 0 = not init, 1 = initialized
    volatile LONG ShuttingDown;         // 0 = running, 1 = shutting down

    //
    // Timer list
    //
    LIST_ENTRY TimerList;
    KSPIN_LOCK TimerListLock;
    volatile LONG TimerCount;

    //
    // Timer wheel for deadline-miss detection
    //
    TM_WHEEL_SLOT Wheel[TM_WHEEL_SIZE];
    volatile LONG CurrentSlot;          // LONG for InterlockedIncrement
    KTIMER WheelTimer;
    KDPC WheelDpc;

    //
    // ID generation — uses InterlockedIncrement, never returns 0
    //
    volatile LONG NextTimerId;

    //
    // Device object for IoAllocateWorkItem (WorkItemCallback support)
    //
    PDEVICE_OBJECT DeviceObject;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TimersCreated;
        volatile LONG64 TimersFired;
        volatile LONG64 TimersCancelled;
        volatile LONG64 TimersMissed;
        volatile LONG64 CoalescedTimers;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Work item drain support — tracks in-flight work items so
    // TmShutdown can wait for them before freeing timer memory.
    // KeFlushQueuedDpcs only drains DPCs, not work items queued
    // by those DPCs via IoQueueWorkItem.
    //
    volatile LONG PendingWorkItems;
    KEVENT AllWorkItemsDrained;

    //
    // Configuration
    //
    struct {
        ULONG DefaultToleranceMs;
        BOOLEAN EnableCoalescing;
        BOOLEAN EnableHighResolution;
    } Config;

} TM_MANAGER, *PTM_MANAGER;

//=============================================================================
// Timer Options (passed to create functions)
//=============================================================================

typedef struct _TM_TIMER_OPTIONS {
    TM_TIMER_TYPE Type;
    TM_TIMER_FLAGS Flags;
    ULONG ToleranceMs;
    ULONG CoalesceGroup;
    PCSTR Name;
    PVOID Context;                      // If ContextSize > 0, data is COPIED
    ULONG ContextSize;                  // 0 = caller owns Context lifetime
} TM_TIMER_OPTIONS, *PTM_TIMER_OPTIONS;

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
TmInitialize(
    _In_opt_ PDEVICE_OBJECT DeviceObject,
    _Out_ PTM_MANAGER* Manager
    );

VOID
TmShutdown(
    _Inout_ PTM_MANAGER Manager
    );

//=============================================================================
// Public API - Timer Creation
//=============================================================================

NTSTATUS
TmCreateOneShot(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG DelayMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    );

NTSTATUS
TmCreatePeriodic(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    );

NTSTATUS
TmCreateAbsolute(
    _In_ PTM_MANAGER Manager,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    );

//=============================================================================
// Public API - Timer Control
//=============================================================================

NTSTATUS
TmStart(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

NTSTATUS
TmStop(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

NTSTATUS
TmCancel(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _In_ BOOLEAN Wait
    );

NTSTATUS
TmReset(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

NTSTATUS
TmSetPeriod(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _In_ ULONG NewPeriodMs
    );

//=============================================================================
// Public API - Timer Query
//=============================================================================

NTSTATUS
TmGetState(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _Out_ PLONG State
    );

NTSTATUS
TmGetRemaining(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _Out_ PLARGE_INTEGER Remaining
    );

BOOLEAN
TmIsActive(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

//=============================================================================
// Public API - Bulk Operations
//=============================================================================

VOID
TmCancelAll(
    _In_ PTM_MANAGER Manager,
    _In_ BOOLEAN Wait
    );

VOID
TmCancelGroup(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG CoalesceGroup,
    _In_ BOOLEAN Wait
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _TM_STATISTICS {
    ULONG ActiveTimers;
    ULONG64 TimersCreated;
    ULONG64 TimersFired;
    ULONG64 TimersCancelled;
    ULONG64 TimersMissed;
    ULONG64 CoalescedTimers;
    LARGE_INTEGER UpTime;
} TM_STATISTICS, *PTM_STATISTICS;

NTSTATUS
TmGetStatistics(
    _In_ PTM_MANAGER Manager,
    _Out_ PTM_STATISTICS Stats
    );

VOID
TmResetStatistics(
    _Inout_ PTM_MANAGER Manager
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Convert milliseconds to 100-nanosecond intervals (negative for relative)
//
#define TM_MS_TO_RELATIVE(ms)  (-(LONGLONG)(ms) * 10000LL)
#define TM_SEC_TO_RELATIVE(sec) TM_MS_TO_RELATIVE((sec) * 1000)
#define TM_MIN_TO_RELATIVE(min) TM_SEC_TO_RELATIVE((min) * 60)

//
// Invalid timer ID sentinel
//
#define TM_INVALID_TIMER_ID     0

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_TIMER_MANAGER_H_
