/*++
    ShadowStrike Next-Generation Antivirus
    Module: TimerManager.h
    
    Purpose: Centralized timer management for periodic tasks,
             timeouts, and scheduled work in the kernel driver.
             
    Architecture:
    - High-resolution timer support via KeSetCoalescableTimer
    - Timer wheel for efficient timeout management
    - One-shot and periodic timers
    - Timer coalescing for power efficiency
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

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
#define TM_WHEEL_SIZE               256     // Slots in timer wheel
#define TM_WHEEL_RESOLUTION_MS      10      // Resolution per slot
#define TM_WHEEL_SPAN_MS            (TM_WHEEL_SIZE * TM_WHEEL_RESOLUTION_MS)

// Coalescing groups
#define TM_COALESCE_GROUP_TELEMETRY     1
#define TM_COALESCE_GROUP_MAINTENANCE   2
#define TM_COALESCE_GROUP_STATISTICS    3

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
    TmFlag_WorkItemCallback     = 0x00000010,   // Callback queued as work item
    TmFlag_AutoDelete           = 0x00000020,   // Delete after one-shot fires
    TmFlag_Synchronized         = 0x00000040,   // Synchronize with cancel
} TM_TIMER_FLAGS;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*TM_TIMER_CALLBACK)(
    _In_ ULONG TimerId,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Timer Object
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
    CHAR Name[32];
    TM_TIMER_TYPE Type;
    TM_TIMER_FLAGS Flags;
    volatile TM_TIMER_STATE State;
    
    //
    // Timing parameters
    //
    LARGE_INTEGER DueTime;              // When to fire (absolute)
    LARGE_INTEGER Period;               // Period for periodic timers
    ULONG ToleranceMs;                  // Tolerance for coalescing
    
    //
    // Callback
    //
    TM_TIMER_CALLBACK Callback;
    PVOID Context;
    ULONG ContextSize;
    
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
    volatile BOOLEAN CancelRequested;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY WheelEntry;
    
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
    // Initialization state
    //
    BOOLEAN Initialized;
    volatile BOOLEAN ShuttingDown;
    
    //
    // Timer list
    //
    LIST_ENTRY TimerList;
    KSPIN_LOCK TimerListLock;
    volatile LONG TimerCount;
    
    //
    // Timer wheel for efficient timeout management
    //
    TM_WHEEL_SLOT Wheel[TM_WHEEL_SIZE];
    volatile ULONG CurrentSlot;
    KTIMER WheelTimer;
    KDPC WheelDpc;
    
    //
    // ID generation
    //
    volatile LONG NextTimerId;
    
    //
    // Work queue integration (for WorkItem callbacks)
    //
    PVOID WorkQueue;                    // PAWQ_MANAGER
    
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
    // Configuration
    //
    struct {
        ULONG DefaultToleranceMs;
        BOOLEAN EnableCoalescing;
        BOOLEAN EnableHighResolution;
    } Config;
    
} TM_MANAGER, *PTM_MANAGER;

//=============================================================================
// Timer Options
//=============================================================================

typedef struct _TM_TIMER_OPTIONS {
    TM_TIMER_TYPE Type;
    TM_TIMER_FLAGS Flags;
    ULONG ToleranceMs;
    ULONG CoalesceGroup;
    PCSTR Name;
    PVOID Context;
    ULONG ContextSize;
} TM_TIMER_OPTIONS, *PTM_TIMER_OPTIONS;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Initialize the timer manager
//
NTSTATUS
TmInitialize(
    _Out_ PTM_MANAGER* Manager
    );

//
// Shutdown the timer manager
//
VOID
TmShutdown(
    _Inout_ PTM_MANAGER Manager
    );

//
// Set work queue for WorkItem callbacks
//
NTSTATUS
TmSetWorkQueue(
    _Inout_ PTM_MANAGER Manager,
    _In_ PVOID WorkQueue
    );

//=============================================================================
// Public API - Timer Creation
//=============================================================================

//
// Create a one-shot timer
//
NTSTATUS
TmCreateOneShot(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG DelayMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    );

//
// Create a periodic timer
//
NTSTATUS
TmCreatePeriodic(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG PeriodMs,
    _In_ TM_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTM_TIMER_OPTIONS Options,
    _Out_ PULONG TimerId
    );

//
// Create timer with absolute due time
//
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

//
// Start a timer
//
NTSTATUS
TmStart(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

//
// Stop (pause) a timer
//
NTSTATUS
TmStop(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

//
// Cancel and delete a timer
//
NTSTATUS
TmCancel(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _In_ BOOLEAN Wait
    );

//
// Reset a timer (restart with same parameters)
//
NTSTATUS
TmReset(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

//
// Modify timer period
//
NTSTATUS
TmSetPeriod(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _In_ ULONG NewPeriodMs
    );

//=============================================================================
// Public API - Timer Query
//=============================================================================

//
// Get timer state
//
NTSTATUS
TmGetState(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _Out_ PTM_TIMER_STATE State
    );

//
// Get time until next fire
//
NTSTATUS
TmGetRemaining(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId,
    _Out_ PLARGE_INTEGER Remaining
    );

//
// Check if timer is active
//
BOOLEAN
TmIsActive(
    _In_ PTM_MANAGER Manager,
    _In_ ULONG TimerId
    );

//=============================================================================
// Public API - Bulk Operations
//=============================================================================

//
// Cancel all timers
//
VOID
TmCancelAll(
    _In_ PTM_MANAGER Manager,
    _In_ BOOLEAN Wait
    );

//
// Cancel timers in a coalesce group
//
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
#define TM_MS_TO_RELATIVE(ms) (-(LONGLONG)(ms) * 10000LL)
#define TM_SEC_TO_RELATIVE(sec) TM_MS_TO_RELATIVE((sec) * 1000)
#define TM_MIN_TO_RELATIVE(min) TM_SEC_TO_RELATIVE((min) * 60)

#ifdef __cplusplus
}
#endif
