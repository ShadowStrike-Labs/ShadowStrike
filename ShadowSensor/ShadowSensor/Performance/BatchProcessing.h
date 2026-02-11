/*++
    ShadowStrike Next-Generation Antivirus
    Module: BatchProcessing.h - Event batch processing

    Purpose: Collects individual events into batches and delivers them
             to a registered callback on a dedicated PASSIVE_LEVEL thread.
             Batches are flushed either when the batch reaches a size
             threshold or when a configurable age timer expires.

    Architecture:
    - BP_PROCESSOR is opaque; internal state is defined only in .c.
    - All public APIs run at IRQL PASSIVE_LEVEL except BpQueueEvent
      which is safe up to DISPATCH_LEVEL so WFP/minifilter callouts
      can enqueue events directly.
    - BpQueueEvent uses a spin lock (short hold) for the active batch.
    - Event data is copied on enqueue; caller retains ownership of input.
    - Rundown protection prevents shutdown while operations are in-flight.
    - BpStop flushes the current batch before stopping the thread so
      no queued events are silently lost.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//=============================================================================
// Pool Tags & Limits
//=============================================================================

#define BP_POOL_TAG             'HCPB'
#define BP_POOL_TAG_EVENT       'ECPB'
#define BP_POOL_TAG_BATCH       'BCPB'
#define BP_MAX_BATCH_SIZE       1000
#define BP_MAX_EVENT_DATA_SIZE  (64 * 1024)     // 64 KB per event
#define BP_MAX_QUEUED_BATCHES   64
#define BP_DEFAULT_BATCH_SIZE   100
#define BP_DEFAULT_MAX_AGE_MS   1000            // 1 second

//=============================================================================
// Event structure — variable-length, always pool-allocated
//=============================================================================

typedef struct _BP_EVENT {
    ULONG Type;
    SIZE_T DataSize;
    UCHAR Data[ANYSIZE_ARRAY];
} BP_EVENT, *PBP_EVENT;

//=============================================================================
// Callback type — invoked at PASSIVE_LEVEL on the processing thread
//=============================================================================

typedef VOID (*BP_BATCH_CALLBACK)(
    _In_reads_(EventCount) PBP_EVENT* Events,
    _In_ ULONG EventCount,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Opaque processor handle
//=============================================================================

typedef struct _BP_PROCESSOR BP_PROCESSOR, *PBP_PROCESSOR;

//=============================================================================
// Statistics (read-only snapshot)
//=============================================================================

typedef struct _BP_STATISTICS {
    LONG64 EventsQueued;
    LONG64 BatchesProcessed;
    LONG64 EventsProcessed;
    LONG64 EventsDropped;
    ULONG ActiveBatchCount;
    ULONG QueuedBatchCount;
    LARGE_INTEGER UpTime;
} BP_STATISTICS, *PBP_STATISTICS;

//=============================================================================
// Public API
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpInitialize(
    _Out_ PBP_PROCESSOR* Processor
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
BpShutdown(
    _Inout_ PBP_PROCESSOR Processor
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpSetBatchParameters(
    _In_ PBP_PROCESSOR Processor,
    _In_ ULONG MaxSize,
    _In_ ULONG MaxAgeMs
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpRegisterCallback(
    _In_ PBP_PROCESSOR Processor,
    _In_ BP_BATCH_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
BpQueueEvent(
    _In_ PBP_PROCESSOR Processor,
    _In_ ULONG Type,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpFlush(
    _In_ PBP_PROCESSOR Processor
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpStart(
    _In_ PBP_PROCESSOR Processor
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpStop(
    _In_ PBP_PROCESSOR Processor
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
BpGetStatistics(
    _In_ PBP_PROCESSOR Processor,
    _Out_ PBP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
