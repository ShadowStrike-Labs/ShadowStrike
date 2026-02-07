/*++
    ShadowStrike Next-Generation Antivirus
    Module: BatchProcessing.h - Event batch processing
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define BP_POOL_TAG 'HCPB'
#define BP_MAX_BATCH_SIZE 1000

typedef struct _BP_EVENT {
    ULONG Type;
    SIZE_T DataSize;
    UCHAR Data[ANYSIZE_ARRAY];
} BP_EVENT, *PBP_EVENT;

typedef VOID (*BP_BATCH_CALLBACK)(
    _In_ PBP_EVENT* Events,
    _In_ ULONG EventCount,
    _In_opt_ PVOID Context
);

typedef struct _BP_BATCH {
    PBP_EVENT Events[BP_MAX_BATCH_SIZE];
    volatile LONG EventCount;
    LARGE_INTEGER OldestEvent;
    LIST_ENTRY ListEntry;
} BP_BATCH, *PBP_BATCH;

typedef struct _BP_PROCESSOR {
    BOOLEAN Initialized;
    
    // Current batch
    PBP_BATCH CurrentBatch;
    KSPIN_LOCK BatchLock;
    
    // Ready batches
    LIST_ENTRY ReadyQueue;
    KSPIN_LOCK QueueLock;
    volatile LONG QueuedBatches;
    
    // Processing thread
    PKTHREAD ProcessingThread;
    KEVENT NewBatchEvent;
    KEVENT StopEvent;
    BOOLEAN StopRequested;
    
    // Batch settings
    ULONG MaxBatchSize;
    ULONG MaxBatchAgeMs;
    
    // Callback
    BP_BATCH_CALLBACK BatchCallback;
    PVOID CallbackContext;
    
    // Timer for batch aging
    KTIMER BatchTimer;
    KDPC BatchDpc;
    
    struct {
        volatile LONG64 EventsQueued;
        volatile LONG64 BatchesProcessed;
        volatile LONG64 EventsProcessed;
        LARGE_INTEGER StartTime;
    } Stats;
} BP_PROCESSOR, *PBP_PROCESSOR;

NTSTATUS BpInitialize(_Out_ PBP_PROCESSOR* Processor);
VOID BpShutdown(_Inout_ PBP_PROCESSOR Processor);
NTSTATUS BpSetBatchParameters(_In_ PBP_PROCESSOR Processor, _In_ ULONG MaxSize, _In_ ULONG MaxAgeMs);
NTSTATUS BpRegisterCallback(_In_ PBP_PROCESSOR Processor, _In_ BP_BATCH_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS BpQueueEvent(_In_ PBP_PROCESSOR Processor, _In_ ULONG Type, _In_ PVOID Data, _In_ SIZE_T DataSize);
NTSTATUS BpFlush(_In_ PBP_PROCESSOR Processor);
NTSTATUS BpStart(_In_ PBP_PROCESSOR Processor);
NTSTATUS BpStop(_In_ PBP_PROCESSOR Processor);

#ifdef __cplusplus
}
#endif
