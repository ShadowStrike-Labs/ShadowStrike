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
    Module: DeferredProcedure.h

    Purpose:
        Pre-allocated DPC (Deferred Procedure Call) object pool for
        high-IRQL deferred work in the ShadowStrike kernel sensor.

    Architecture:
        - Fixed-size object pool allocated at PASSIVE_LEVEL (init time).
        - Lock-free SLIST for O(1) alloc/free at any IRQL <= DISPATCH.
        - Threaded DPCs for operations that may lower to PASSIVE_LEVEL.
        - Per-processor targeting via KeSetTargetProcessorDpcEx (>64 CPU safe).
        - ActiveCount + DrainEvent for deterministic shutdown without spin-wait.
        - No SEH in DPC callbacks (undefined behavior at DISPATCH_LEVEL).
        - No chaining (removed: fundamentally unsafe without ownership model).
        - Inline context capped at 64 bytes; larger payloads use external API.

    IRQL contract:
        DpcInitialize   — PASSIVE_LEVEL (INIT section)
        DpcShutdown     — PASSIVE_LEVEL (PAGE section)
        DpcQueue*       — any IRQL <= DISPATCH_LEVEL
        DpcGetStatistics— any IRQL <= DISPATCH_LEVEL

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

// ============================================================================
// Pool Tags
// ============================================================================

#define DPC_POOL_TAG    'cPDd'  // dDPc — DPC pool

// ============================================================================
// Configuration Constants
// ============================================================================

#define DPC_POOL_SIZE_DEFAULT       256
#define DPC_POOL_SIZE_MIN           32
#define DPC_POOL_SIZE_MAX           4096

/**
 * Maximum inline context bytes stored inside DPC_OBJECT.
 * Keeps sizeof(DPC_OBJECT) compact.  Callers needing more should
 * use DpcQueueExternal with caller-managed lifetime.
 */
#define DPC_MAX_CONTEXT_SIZE        64

// ============================================================================
// DPC Types
// ============================================================================

typedef enum _DPC_TYPE {
    DpcType_Normal = 0,             /**< Normal DPC, medium importance.       */
    DpcType_Threaded,               /**< Threaded DPC — may lower to PASSIVE. */
    DpcType_HighImportance,         /**< Queued at front of DPC queue.        */
    DpcType_LowImportance           /**< Queued at back of DPC queue.         */
} DPC_TYPE;

// ============================================================================
// DPC State
// ============================================================================

typedef enum _DPC_STATE {
    DpcState_Free = 0,
    DpcState_Allocated,
    DpcState_Queued,
    DpcState_Running,
    DpcState_Completed
} DPC_STATE;

// ============================================================================
// Callback Types
// ============================================================================

/**
 * DPC work callback.  Runs at DISPATCH_LEVEL (normal DPC) or
 * PASSIVE/APC (threaded DPC).  Must not raise exceptions.
 */
typedef VOID (*DPC_CALLBACK)(
    _In_opt_ PVOID Context,
    _In_ ULONG ContextSize
    );

/**
 * Optional completion notification after DPC callback returns.
 * Runs at the same IRQL as the DPC callback.
 */
typedef VOID (*DPC_COMPLETION_CALLBACK)(
    _In_ NTSTATUS Status,
    _In_opt_ PVOID CompletionContext
    );

// ============================================================================
// DPC Object  (pool element)
//
// SLIST_ENTRY MUST be the first field so that the struct's natural
// alignment (DECLSPEC_ALIGN) guarantees the 16-byte alignment
// required by InterlockedPushEntrySList / InterlockedPopEntrySList
// on x64 (CMPXCHG16B).
// ============================================================================

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DPC_OBJECT {

    /** Free-list linkage — MUST be first for SLIST alignment. */
    SLIST_ENTRY FreeListEntry;

    /** Kernel DPC object. */
    KDPC Dpc;

    /** Per-object identifier (1-based, stable across reuse). */
    ULONG ObjectId;

    DPC_TYPE Type;
    volatile DPC_STATE State;

    /** Work callback + optional completion. */
    DPC_CALLBACK Callback;
    DPC_COMPLETION_CALLBACK CompletionCallback;
    PVOID CompletionContext;

    /** Inline context for small payloads (<= DPC_MAX_CONTEXT_SIZE). */
    UCHAR InlineContext[DPC_MAX_CONTEXT_SIZE];

    /** External context pointer — caller manages lifetime. */
    PVOID ExternalContext;

    ULONG ContextSize;
    BOOLEAN UseInlineContext;

    /** Processor targeting (PROCESSOR_NUMBER for >64 CPU support). */
    PROCESSOR_NUMBER TargetProcessor;
    BOOLEAN ProcessorTargeted;

    /** Timestamps for diagnostics. */
    LARGE_INTEGER QueueTime;
    LARGE_INTEGER ExecuteTime;
    LARGE_INTEGER CompleteTime;

} DPC_OBJECT, *PDPC_OBJECT;

// ============================================================================
// DPC Manager
// ============================================================================

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DPC_MANAGER {

    /** Set TRUE after successful init; cleared at start of shutdown. */
    volatile LONG Initialized;

    // ---- Lock-free object pool ----

    SLIST_HEADER FreePool;
    volatile LONG FreeCount;
    volatile LONG AllocatedCount;
    ULONG PoolSize;

    /** Contiguous backing array — freed in DpcShutdown. */
    PDPC_OBJECT PoolMemory;
    SIZE_T PoolMemorySize;

    // ---- Shutdown drain ----

    /**
     * Number of DPC callbacks currently in-flight.
     * Incremented inside DPC routine, decremented in complete path.
     * When it reaches 0 AND the manager is shutting down, DrainEvent
     * is signaled so DpcShutdown can proceed safely.
     */
    volatile LONG ActiveCount;
    KEVENT DrainEvent;

    // ---- Statistics (individually atomic, not collectively) ----

    volatile LONG64 TotalQueued;
    volatile LONG64 TotalExecuted;
    volatile LONG64 TotalCancelled;
    volatile LONG64 PoolExhausted;
    LARGE_INTEGER StartTime;

} DPC_MANAGER, *PDPC_MANAGER;

// ============================================================================
// DPC Options  (passed to DpcQueue)
// ============================================================================

typedef struct _DPC_OPTIONS {
    DPC_TYPE Type;
    PROCESSOR_NUMBER TargetProcessor;   /**< Ignored unless Targeted is TRUE. */
    BOOLEAN Targeted;                   /**< TRUE to pin DPC to a processor.  */
    DPC_COMPLETION_CALLBACK CompletionCallback;
    PVOID CompletionContext;
} DPC_OPTIONS, *PDPC_OPTIONS;

// ============================================================================
// Public API — Initialization
// ============================================================================

/**
 * Allocate and initialize a DPC manager with a pre-allocated object pool.
 *
 * @param Manager   Receives the new manager pointer.  Set to NULL on failure.
 * @param PoolSize  Desired pool size (clamped to [DPC_POOL_SIZE_MIN, MAX]).
 *                  Pass 0 for DPC_POOL_SIZE_DEFAULT.
 * @return STATUS_SUCCESS or error.
 *
 * IRQL: PASSIVE_LEVEL (INIT section).
 */
NTSTATUS
DpcInitialize(
    _Out_ PDPC_MANAGER* Manager,
    _In_ ULONG PoolSize
    );

/**
 * Drain all in-flight DPCs, flush system DPC queues, free resources.
 * On return, *Manager is NULL and the pointer is invalid.
 *
 * IRQL: PASSIVE_LEVEL.
 */
VOID
DpcShutdown(
    _Inout_ PDPC_MANAGER* Manager
    );

// ============================================================================
// Public API — DPC Queue Operations
// ============================================================================

/**
 * Queue a DPC with an inline copy of the context buffer.
 * ContextSize must be <= DPC_MAX_CONTEXT_SIZE.
 * Safe to call at any IRQL <= DISPATCH_LEVEL.
 */
NTSTATUS
DpcQueue(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PDPC_OPTIONS Options
    );

/**
 * Queue a DPC with caller-managed external context.
 * The caller must keep Context valid until the DPC completes.
 * ContextSize is passed through to the callback for convenience.
 */
NTSTATUS
DpcQueueExternal(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_ PVOID Context,
    _In_ ULONG ContextSize,
    _In_opt_ PDPC_OPTIONS Options
    );

/**
 * Queue a DPC targeted at a specific processor.
 * ProcessorGroup/ProcessorNumber identify the logical CPU.
 */
NTSTATUS
DpcQueueOnProcessor(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber
    );

/**
 * Queue a threaded DPC (may execute at PASSIVE_LEVEL).
 */
NTSTATUS
DpcQueueThreaded(
    _In_ PDPC_MANAGER Manager,
    _In_ DPC_CALLBACK Callback,
    _In_reads_bytes_opt_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize
    );

// ============================================================================
// Public API — Statistics
// ============================================================================

typedef struct _DPC_STATISTICS {
    ULONG PoolSize;
    ULONG FreeCount;
    ULONG AllocatedCount;
    ULONG64 TotalQueued;
    ULONG64 TotalExecuted;
    ULONG64 TotalCancelled;
    ULONG64 PoolExhausted;
    LARGE_INTEGER UpTime;
} DPC_STATISTICS, *PDPC_STATISTICS;

/**
 * Snapshot current statistics.  Not collectively atomic — individual
 * counters are read atomically but the snapshot may be slightly skewed.
 */
NTSTATUS
DpcGetStatistics(
    _In_ PDPC_MANAGER Manager,
    _Out_ PDPC_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
