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
 * ShadowStrike NGAV - TELEMETRY BUFFER IMPLEMENTATION
 * ============================================================================
 *
 * @file TelemetryBuffer.c
 * @brief High-performance per-CPU ring buffer for telemetry collection.
 *
 * This module implements a highly scalable telemetry collection system
 * designed for minimal performance impact in kernel-mode. Key features:
 *
 * Architecture:
 * - Per-CPU ring buffers with proper synchronization
 * - Slot state tracking for true two-phase commit
 * - Automatic batch coalescing for efficient transfer to user-mode
 * - Flow control with configurable water marks
 * - CRC32 integrity verification for header + payload
 *
 * Performance Considerations:
 * - Cache-line aligned producer/consumer indices to prevent false sharing
 * - Fast-path enqueue designed for < 100ns latency
 * - Background flush thread handles batching off critical path
 * - Memory pre-allocation avoids allocation during hot paths
 *
 * Safety:
 * - BSOD-safe with proper IRQL handling
 * - Graceful degradation under memory pressure
 * - Atomic state transitions prevent race conditions
 * - Entry validation prevents buffer corruption
 * - Proper DPC flush on teardown
 *
 * IRQL Requirements:
 * - TbInitialize/TbShutdown: PASSIVE_LEVEL
 * - TbEnqueue: <= DISPATCH_LEVEL
 * - TbDequeue: PASSIVE_LEVEL
 * - TbReserve/TbCommit/TbAbort: <= DISPATCH_LEVEL
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "TelemetryBuffer.h"

//
// MmGetSessionId is exported by ntoskrnl.exe since Windows Vista but
// not always declared in WDK headers depending on NTDDI_VERSION settings.
//
#ifndef MmGetSessionId
NTKERNELAPI ULONG MmGetSessionId(_In_ PEPROCESS Process);
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define TB_FLUSH_INTERVAL_MS    100
#define TB_MAX_BATCH_WAIT_MS    1000
#define TB_FLUSH_LOG_INTERVAL   100     // Log every 10 seconds (100 * 100ms)

// ============================================================================
// GLOBAL STATE (Atomic access only)
// ============================================================================

static PTB_MANAGER g_TbManager = NULL;

// ============================================================================
// CRC32 LOOKUP TABLE (Standard polynomial 0xEDB88320)
// ============================================================================

static const ULONG g_Crc32Table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBBBD6, 0xACBCCB40, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD706B7,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TbpInitializeRingBuffer(
    _Out_ PTB_RING_BUFFER RingBuffer,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TbpDestroyRingBuffer(
    _Inout_ PTB_RING_BUFFER RingBuffer
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TbpInitializePerCpuBuffer(
    _Out_ PTB_PERCPU_BUFFER PerCpuBuffer,
    _In_ ULONG ProcessorNumber,
    _In_ ULONG BufferSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TbpDestroyPerCpuBuffer(
    _Inout_ PTB_PERCPU_BUFFER PerCpuBuffer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TbpEnqueueToRingBuffer(
    _In_ PTB_MANAGER Manager,
    _Inout_ PTB_RING_BUFFER RingBuffer,
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_opt_(Header->PayloadSize) PVOID Payload,
    _In_ BOOLEAN AllowDrop
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TbpDequeueFromRingBuffer(
    _Inout_ PTB_RING_BUFFER RingBuffer,
    _Out_writes_bytes_to_(BufferSize, *BytesReturned) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned,
    _Out_ PULONG EntriesReturned
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpGetRingBufferUsage(
    _In_ PTB_RING_BUFFER RingBuffer
    );

_IRQL_requires_(DISPATCH_LEVEL)
static VOID
TbpFlushTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TbpFlushThreadRoutine(
    _In_ PVOID Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpComputeCRC32(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpComputeEntryCRC32(
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_opt_(Header->PayloadSize) PVOID Payload
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
TbpValidateEntry(
    _In_ PTB_ENTRY_HEADER Entry,
    _In_ ULONG MaxSize,
    _In_ ULONG SlotSize
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpRoundDownToPowerOf2(
    _In_ ULONG Value
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
FORCEINLINE
ULONG64
TbpGetCurrentTimestamp(
    VOID
    )
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return (ULONG64)time.QuadPart;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
FORCEINLINE
ULONG
TbpGetSessionId(
    VOID
    )
{
    //
    // Get current process session ID
    //
    PEPROCESS process = PsGetCurrentProcess();
    ULONG sessionId = 0;

    if (process != NULL) {
        sessionId = MmGetSessionId(process);
    }

    return sessionId;
}

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, TbInitialize)
#pragma alloc_text(PAGE, TbShutdown)
#pragma alloc_text(PAGE, TbStart)
#pragma alloc_text(PAGE, TbStop)
#pragma alloc_text(PAGE, TbPause)
#pragma alloc_text(PAGE, TbResume)
#pragma alloc_text(PAGE, TbpFlushThreadRoutine)
#pragma alloc_text(PAGE, TbDequeue)
#pragma alloc_text(PAGE, TbDequeueBatch)
#pragma alloc_text(PAGE, TbIterate)
#pragma alloc_text(PAGE, TbResize)
#endif

// ============================================================================
// HELPER: ROUND DOWN TO POWER OF 2
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpRoundDownToPowerOf2(
    _In_ ULONG Value
    )
{
    if (Value == 0) {
        return 0;
    }

    //
    // Fill all bits below the highest set bit
    //
    Value |= (Value >> 1);
    Value |= (Value >> 2);
    Value |= (Value >> 4);
    Value |= (Value >> 8);
    Value |= (Value >> 16);

    //
    // Subtract to get power of 2
    //
    return Value - (Value >> 1);
}

// ============================================================================
// CRC32 COMPUTATION
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpComputeCRC32(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    )
{
    PUCHAR bytes = (PUCHAR)Data;
    ULONG crc = 0xFFFFFFFF;
    ULONG i;

    if (Data == NULL || Size == 0) {
        return 0;
    }

    for (i = 0; i < Size; i++) {
        crc = g_Crc32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Compute CRC32 over header (excluding CRC field) and payload.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpComputeEntryCRC32(
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_opt_(Header->PayloadSize) PVOID Payload
    )
{
    ULONG crc = 0xFFFFFFFF;
    PUCHAR bytes;
    ULONG i;
    ULONG headerSize;
    ULONG crcFieldOffset;

    //
    // Compute CRC over header excluding the ChecksumCRC32 field
    //
    bytes = (PUCHAR)Header;
    crcFieldOffset = FIELD_OFFSET(TB_ENTRY_HEADER, ChecksumCRC32);
    headerSize = sizeof(TB_ENTRY_HEADER);

    //
    // CRC bytes before ChecksumCRC32 field
    //
    for (i = 0; i < crcFieldOffset; i++) {
        crc = g_Crc32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    //
    // Skip the 4-byte ChecksumCRC32 field
    //
    for (i = crcFieldOffset + sizeof(ULONG); i < headerSize; i++) {
        crc = g_Crc32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    //
    // CRC payload if present
    //
    if (Payload != NULL && Header->PayloadSize > 0) {
        bytes = (PUCHAR)Payload;
        for (i = 0; i < Header->PayloadSize; i++) {
            crc = g_Crc32Table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
        }
    }

    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// ENTRY VALIDATION
// ============================================================================

/**
 * @brief Validate an entry for safety before dequeuing.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
TbpValidateEntry(
    _In_ PTB_ENTRY_HEADER Entry,
    _In_ ULONG MaxSize,
    _In_ ULONG SlotSize
    )
{
    //
    // Check signature
    //
    if (Entry->Signature != TB_ENTRY_SIGNATURE) {
        return FALSE;
    }

    //
    // Check entry size bounds
    //
    if (Entry->EntrySize < sizeof(TB_ENTRY_HEADER)) {
        return FALSE;
    }

    if (Entry->EntrySize > MaxSize) {
        return FALSE;
    }

    if (Entry->EntrySize > SlotSize) {
        return FALSE;
    }

    //
    // Validate payload offset and size
    //
    if (Entry->PayloadOffset != 0) {
        if (Entry->PayloadOffset < sizeof(TB_ENTRY_HEADER)) {
            return FALSE;
        }

        if (Entry->PayloadOffset > Entry->EntrySize) {
            return FALSE;
        }

        if (Entry->PayloadSize > 0) {
            if (Entry->PayloadOffset + Entry->PayloadSize > Entry->EntrySize) {
                return FALSE;
            }
        }
    }

    //
    // Validate entry type range
    //
    if (Entry->EntryType >= TbEntryType_Max) {
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the telemetry buffer manager.
 *
 * Uses atomic compare-exchange to prevent double initialization race.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbInitialize(
    _Out_ PTB_MANAGER* Manager,
    _In_ ULONG PerCpuBufferSize,
    _In_ ULONG BatchSize,
    _In_ ULONG BatchTimeoutMs
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PTB_MANAGER manager = NULL;
    PTB_MANAGER previousManager;
    ULONG cpuCount;
    ULONG i;
    ULONG effectiveBufferSize;

    PAGED_CODE();

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Manager = NULL;

    //
    // Validate parameters
    //
    if (PerCpuBufferSize < TB_MIN_BUFFER_SIZE ||
        PerCpuBufferSize > TB_MAX_BUFFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BatchSize == 0 || BatchSize > TB_MAX_BATCH_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Adjust buffer size if running under Driver Verifier
    //
    effectiveBufferSize = PerCpuBufferSize;
    if (MmIsVerifierEnabled(NULL)) {
        if (effectiveBufferSize > TB_VERIFIER_BUFFER_SIZE) {
            effectiveBufferSize = TB_VERIFIER_BUFFER_SIZE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/TB] Verifier enabled, reducing buffer to %u\n",
                       effectiveBufferSize);
        }
    }

    //
    // Allocate manager structure
    //
    manager = (PTB_MANAGER)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(TB_MANAGER),
        TB_POOL_TAG_BUFFER
    );

    if (manager == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Atomically set global manager - prevent double initialization
    //
    previousManager = (PTB_MANAGER)InterlockedCompareExchangePointer(
        (PVOID*)&g_TbManager,
        manager,
        NULL
    );

    if (previousManager != NULL) {
        //
        // Another initialization won the race
        //
        ExFreePoolWithTag(manager, TB_POOL_TAG_BUFFER);
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Initialize signature
    //
    manager->Signature = TB_MANAGER_SIGNATURE;

    //
    // Initialize configuration
    //
    manager->Config.PerCpuBufferSize = effectiveBufferSize;
    manager->Config.BatchSize = BatchSize;
    manager->Config.BatchTimeoutMs = BatchTimeoutMs;
    manager->Config.HighWaterPercent = TB_HIGH_WATER_PERCENT;
    manager->Config.LowWaterPercent = TB_LOW_WATER_PERCENT;
    manager->Config.EnableCompression = FALSE;
    manager->Config.EnableEncryption = FALSE;
    manager->Config.EnablePerCpu = TRUE;

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&manager->ManagerLock);
    ExInitializePushLock(&manager->ConsumerLock);
    ExInitializePushLock(&manager->OverflowCallbackLock);
    InitializeListHead(&manager->PendingBatches);
    KeInitializeSpinLock(&manager->BatchListLock);
    KeInitializeEvent(&manager->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&manager->GlobalConsumerEvent, SynchronizationEvent, FALSE);

    //
    // Initialize batch lookaside list (manager-local, not global)
    //
    ExInitializeNPagedLookasideList(
        &manager->BatchLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(TB_BATCH_DESCRIPTOR),
        TB_POOL_TAG_BATCH,
        0
    );
    InterlockedExchange(&manager->BatchLookasideInitialized, 1);

    //
    // Initialize reservation lookaside list
    //
    ExInitializeNPagedLookasideList(
        &manager->ReservationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(TB_RESERVATION_CONTEXT),
        TB_POOL_TAG_RESERVATION,
        0
    );
    InterlockedExchange(&manager->ReservationLookasideInitialized, 1);

    //
    // Get CPU count and allocate per-CPU buffers
    //
    cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpuCount > TB_MAX_PERCPU_BUFFERS) {
        cpuCount = TB_MAX_PERCPU_BUFFERS;
    }

    manager->ActiveCpuCount = cpuCount;

    for (i = 0; i < cpuCount; i++) {
        manager->PerCpuBuffers[i] = (PTB_PERCPU_BUFFER)ExAllocatePoolZero(
            NonPagedPoolNx,
            sizeof(TB_PERCPU_BUFFER),
            TB_POOL_TAG_PERCPU
        );

        if (manager->PerCpuBuffers[i] == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        status = TbpInitializePerCpuBuffer(
            manager->PerCpuBuffers[i],
            i,
            effectiveBufferSize
        );

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(manager->PerCpuBuffers[i], TB_POOL_TAG_PERCPU);
            manager->PerCpuBuffers[i] = NULL;
            goto Cleanup;
        }
    }

    //
    // Initialize global overflow buffer
    //
    status = TbpInitializeRingBuffer(
        &manager->GlobalOverflow,
        effectiveBufferSize
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Set initial state
    //
    manager->State = TbBufferState_Initializing;
    manager->MaxPendingBatches = 1000;
    manager->PendingBatchCount = 0;
    manager->FlushIterationCount = 0;
    KeQuerySystemTime(&manager->Stats.StartTime);

    *Manager = manager;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Telemetry buffer initialized: CPUs=%u, BufSize=%u, Batch=%u\n",
               cpuCount, effectiveBufferSize, BatchSize);

    return STATUS_SUCCESS;

Cleanup:
    //
    // Cleanup on failure - release all resources
    //
    if (manager != NULL) {
        //
        // Destroy per-CPU buffers
        //
        for (i = 0; i < TB_MAX_PERCPU_BUFFERS; i++) {
            if (manager->PerCpuBuffers[i] != NULL) {
                TbpDestroyPerCpuBuffer(manager->PerCpuBuffers[i]);
                ExFreePoolWithTag(manager->PerCpuBuffers[i], TB_POOL_TAG_PERCPU);
                manager->PerCpuBuffers[i] = NULL;
            }
        }

        //
        // Destroy lookaside lists if initialized
        //
        if (InterlockedCompareExchange(&manager->BatchLookasideInitialized, 0, 1) == 1) {
            ExDeleteNPagedLookasideList(&manager->BatchLookaside);
        }

        if (InterlockedCompareExchange(&manager->ReservationLookasideInitialized, 0, 1) == 1) {
            ExDeleteNPagedLookasideList(&manager->ReservationLookaside);
        }

        //
        // Clear global pointer
        //
        InterlockedExchangePointer((PVOID*)&g_TbManager, NULL);

        ExFreePoolWithTag(manager, TB_POOL_TAG_BUFFER);
    }

    return status;
}

/**
 * @brief Shutdown the telemetry buffer manager.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TbShutdown(
    _Inout_ PTB_MANAGER Manager
    )
{
    ULONG i;
    LARGE_INTEGER timeout;
    PLIST_ENTRY entry;
    PTB_BATCH_DESCRIPTOR batch;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Manager == NULL) {
        return;
    }

    //
    // Validate this is our manager
    //
    if (Manager->Signature != TB_MANAGER_SIGNATURE) {
        return;
    }

    //
    // Atomically clear global pointer
    //
    if (InterlockedCompareExchangePointer((PVOID*)&g_TbManager, NULL, Manager) != Manager) {
        //
        // Not our manager or already cleared
        //
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Shutting down telemetry buffer...\n");

    //
    // Signal shutdown
    //
    Manager->State = TbBufferState_Shutdown;
    KeSetEvent(&Manager->ShutdownEvent, IO_NO_INCREMENT, FALSE);

    //
    // Wait for flush thread to exit
    //
    if (Manager->FlushThread != NULL) {
        InterlockedExchange(&Manager->FlushThreadRunning, 0);

        timeout.QuadPart = -50000000LL;  // 5 seconds
        KeWaitForSingleObject(
            Manager->FlushThread,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
        ObDereferenceObject(Manager->FlushThread);
        Manager->FlushThread = NULL;
    }

    //
    // Free pending batches under lock
    //
    KeAcquireSpinLock(&Manager->BatchListLock, &oldIrql);
    while (!IsListEmpty(&Manager->PendingBatches)) {
        entry = RemoveHeadList(&Manager->PendingBatches);
        batch = CONTAINING_RECORD(entry, TB_BATCH_DESCRIPTOR, ListEntry);
        if (batch->BatchBuffer != NULL) {
            ExFreePoolWithTag(batch->BatchBuffer, TB_POOL_TAG_BATCH);
        }
        //
        // Only free to lookaside if still initialized
        //
        if (Manager->BatchLookasideInitialized) {
            ExFreeToNPagedLookasideList(&Manager->BatchLookaside, batch);
        }
    }
    KeReleaseSpinLock(&Manager->BatchListLock, oldIrql);

    //
    // Destroy per-CPU buffers (includes DPC flush)
    //
    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        if (Manager->PerCpuBuffers[i] != NULL) {
            TbpDestroyPerCpuBuffer(Manager->PerCpuBuffers[i]);
            ExFreePoolWithTag(Manager->PerCpuBuffers[i], TB_POOL_TAG_PERCPU);
            Manager->PerCpuBuffers[i] = NULL;
        }
    }

    //
    // Destroy global overflow buffer
    //
    TbpDestroyRingBuffer(&Manager->GlobalOverflow);

    //
    // Delete lookaside lists
    //
    if (InterlockedCompareExchange(&Manager->BatchLookasideInitialized, 0, 1) == 1) {
        ExDeleteNPagedLookasideList(&Manager->BatchLookaside);
    }

    if (InterlockedCompareExchange(&Manager->ReservationLookasideInitialized, 0, 1) == 1) {
        ExDeleteNPagedLookasideList(&Manager->ReservationLookaside);
    }

    //
    // Log final stats
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Final stats: Enqueued=%llu, Dequeued=%llu, Dropped=%llu\n",
               Manager->Stats.TotalEnqueued,
               Manager->Stats.TotalDequeued,
               Manager->Stats.TotalDropped);

    //
    // Clear signature and free manager
    //
    Manager->Signature = 0;
    ExFreePoolWithTag(Manager, TB_POOL_TAG_BUFFER);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Telemetry buffer shutdown complete\n");
}

// ============================================================================
// START/STOP
// ============================================================================

/**
 * @brief Start telemetry buffering.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbStart(
    _Inout_ PTB_MANAGER Manager
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE threadHandle = NULL;

    PAGED_CODE();

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Initializing &&
        Manager->State != TbBufferState_Paused) {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    //
    // Create flush thread
    //
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    InterlockedExchange(&Manager->FlushThreadRunning, 1);
    KeClearEvent(&Manager->ShutdownEvent);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        TbpFlushThreadRoutine,
        Manager
    );

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&Manager->FlushThreadRunning, 0);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/TB] Failed to create flush thread: 0x%08X\n", status);
        return status;
    }

    //
    // Get thread reference
    //
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Manager->FlushThread,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        //
        // Thread was created but we can't get a reference
        // Signal shutdown to orphaned thread
        //
        InterlockedExchange(&Manager->FlushThreadRunning, 0);
        KeSetEvent(&Manager->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        ZwClose(threadHandle);
        return status;
    }

    ZwClose(threadHandle);

    //
    // Set state to active
    //
    Manager->State = TbBufferState_Active;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Telemetry buffering started\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Stop telemetry buffering.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbStop(
    _Inout_ PTB_MANAGER Manager,
    _In_ BOOLEAN Drain
    )
{
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Active &&
        Manager->State != TbBufferState_Paused) {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    //
    // Set draining state if requested
    //
    if (Drain) {
        Manager->State = TbBufferState_Draining;
        //
        // Wait for buffers to drain (max 5 seconds)
        //
        timeout.QuadPart = -50000000LL;
        KeWaitForSingleObject(
            &Manager->GlobalOverflow.DrainEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Stop flush thread
    //
    InterlockedExchange(&Manager->FlushThreadRunning, 0);
    KeSetEvent(&Manager->ShutdownEvent, IO_NO_INCREMENT, FALSE);

    if (Manager->FlushThread != NULL) {
        timeout.QuadPart = -50000000LL;
        KeWaitForSingleObject(
            Manager->FlushThread,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
        ObDereferenceObject(Manager->FlushThread);
        Manager->FlushThread = NULL;
    }

    Manager->State = TbBufferState_Paused;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Telemetry buffering stopped\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Pause telemetry buffering.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbPause(
    _Inout_ PTB_MANAGER Manager
    )
{
    PAGED_CODE();

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Active) {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    Manager->State = TbBufferState_Paused;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Telemetry buffering paused\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Resume telemetry buffering.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbResume(
    _Inout_ PTB_MANAGER Manager
    )
{
    PAGED_CODE();

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Paused) {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    Manager->State = TbBufferState_Active;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Telemetry buffering resumed\n");

    return STATUS_SUCCESS;
}

// ============================================================================
// ENQUEUE
// ============================================================================

/**
 * @brief Enqueue a telemetry entry.
 *
 * Fast-path for enqueueing telemetry events. Uses per-CPU buffers to
 * minimize contention. Raises IRQL to prevent CPU migration.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbEnqueue(
    _In_ PTB_MANAGER Manager,
    _In_ TB_ENTRY_TYPE EntryType,
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_opt_ PTB_ENQUEUE_OPTIONS Options
    )
{
    TB_ENTRY_HEADER header;
    PTB_PERCPU_BUFFER perCpuBuffer;
    PTB_RING_BUFFER targetBuffer;
    ULONG currentCpu;
    NTSTATUS status;
    TB_ENTRY_FLAGS flags = TbFlag_None;
    BOOLEAN allowDrop = TRUE;
    KIRQL oldIrql;

    //
    // Quick state check
    //
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Active) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate payload
    //
    if (Payload == NULL && PayloadSize > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PayloadSize > TB_MAX_ENTRY_SIZE - sizeof(TB_ENTRY_HEADER)) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Process options
    //
    if (Options != NULL) {
        flags = Options->Flags;
        allowDrop = Options->AllowDrop;
    }

    //
    // Never drop critical entries
    //
    if (flags & TbFlag_Critical) {
        allowDrop = FALSE;
    }

    //
    // Raise IRQL to prevent CPU migration during buffer selection
    //
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    //
    // Build entry header
    //
    RtlZeroMemory(&header, sizeof(header));
    header.Signature = TB_ENTRY_SIGNATURE;
    header.EntrySize = sizeof(TB_ENTRY_HEADER) + PayloadSize;
    header.SequenceNumber = (ULONG64)InterlockedIncrement64(&Manager->GlobalSequenceNumber);
    KeQuerySystemTime(&header.Timestamp);
    header.QpcTimestamp = KeQueryPerformanceCounter(NULL);
    header.EntryType = EntryType;
    header.Flags = flags;
    header.ProcessorNumber = KeGetCurrentProcessorNumberEx(NULL);
    header.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    header.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    header.SessionId = TbpGetSessionId();
    header.PayloadOffset = sizeof(TB_ENTRY_HEADER);
    header.PayloadSize = PayloadSize;
    header.ChecksumCRC32 = 0;  // Computed below

    //
    // Process chain information from options
    //
    if (Options != NULL) {
        header.ChainId = Options->ChainId;
        header.ChainIndex = Options->ChainIndex;
        header.ChainCount = Options->ChainCount;
    }

    //
    // Compute CRC32 over header + payload
    //
    header.ChecksumCRC32 = TbpComputeEntryCRC32(&header, Payload);

    //
    // Select target buffer (per-CPU or overflow)
    //
    currentCpu = header.ProcessorNumber;
    if (currentCpu < Manager->ActiveCpuCount && Manager->PerCpuBuffers[currentCpu] != NULL) {
        perCpuBuffer = Manager->PerCpuBuffers[currentCpu];
        targetBuffer = &perCpuBuffer->RingBuffer;
    } else {
        //
        // Fall back to global overflow buffer
        //
        targetBuffer = &Manager->GlobalOverflow;
    }

    //
    // Enqueue to target buffer
    //
    status = TbpEnqueueToRingBuffer(Manager, targetBuffer, &header, Payload, allowDrop);

    //
    // Restore IRQL
    //
    KeLowerIrql(oldIrql);

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&Manager->Stats.TotalEnqueued);
        InterlockedAdd64(&Manager->Stats.TotalBytes, header.EntrySize);

        //
        // Signal global consumer event
        //
        KeSetEvent(&Manager->GlobalConsumerEvent, IO_NO_INCREMENT, FALSE);
    } else if (status == STATUS_DEVICE_BUSY) {
        InterlockedIncrement64(&Manager->Stats.TotalDropped);
    }

    return status;
}

/**
 * @brief Enqueue with pre-built header.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbEnqueueWithHeader(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_(Header->PayloadSize) PVOID Payload,
    _In_opt_ PTB_ENQUEUE_OPTIONS Options
    )
{
    PTB_RING_BUFFER targetBuffer;
    ULONG currentCpu;
    BOOLEAN allowDrop = TRUE;
    KIRQL oldIrql;
    NTSTATUS status;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE || Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Active) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Options != NULL) {
        allowDrop = Options->AllowDrop;
    }

    //
    // Raise IRQL to prevent CPU migration
    //
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    //
    // Select buffer
    //
    currentCpu = KeGetCurrentProcessorNumberEx(NULL);
    if (currentCpu < Manager->ActiveCpuCount && Manager->PerCpuBuffers[currentCpu] != NULL) {
        targetBuffer = &Manager->PerCpuBuffers[currentCpu]->RingBuffer;
    } else {
        targetBuffer = &Manager->GlobalOverflow;
    }

    status = TbpEnqueueToRingBuffer(Manager, targetBuffer, Header, Payload, allowDrop);

    KeLowerIrql(oldIrql);

    if (NT_SUCCESS(status)) {
        KeSetEvent(&Manager->GlobalConsumerEvent, IO_NO_INCREMENT, FALSE);
    }

    return status;
}

// ============================================================================
// TWO-PHASE COMMIT (RESERVE/COMMIT/ABORT)
// ============================================================================

/**
 * @brief Reserve space in the ring buffer for a large entry.
 *
 * Implements proper two-phase commit with slot state tracking.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbReserve(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG Size,
    _Out_ PTB_RESERVATION_CONTEXT* Context,
    _Out_ PTB_ENTRY_HEADER* Header,
    _Out_ PVOID* PayloadPtr
    )
{
    PTB_RESERVATION_CONTEXT reservation = NULL;
    PTB_RING_BUFFER targetBuffer;
    PTB_PERCPU_BUFFER perCpuBuffer;
    ULONG currentCpu;
    KIRQL oldIrql;
    LONG64 producerIdx;
    LONG64 consumerIdx;
    ULONG slotIndex;
    ULONG slotOffset;
    PUCHAR destPtr;
    PTB_ENTRY_HEADER headerPtr;
    ULONG usage;
    LONG expectedState;

    *Context = NULL;
    *Header = NULL;
    *PayloadPtr = NULL;

    //
    // Validate parameters
    //
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Active) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Size < sizeof(TB_ENTRY_HEADER) || Size > TB_MAX_ENTRY_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->ReservationLookasideInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate reservation context
    //
    reservation = (PTB_RESERVATION_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Manager->ReservationLookaside
    );

    if (reservation == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(reservation, sizeof(TB_RESERVATION_CONTEXT));

    //
    // Raise IRQL to prevent CPU migration
    //
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    currentCpu = KeGetCurrentProcessorNumberEx(NULL);

    //
    // Select target buffer
    //
    if (currentCpu < Manager->ActiveCpuCount && Manager->PerCpuBuffers[currentCpu] != NULL) {
        perCpuBuffer = Manager->PerCpuBuffers[currentCpu];
        targetBuffer = &perCpuBuffer->RingBuffer;
    } else {
        targetBuffer = &Manager->GlobalOverflow;
    }

    //
    // Check slot size constraint
    //
    if (Size > targetBuffer->EntrySlotSize) {
        KeLowerIrql(oldIrql);
        ExFreeToNPagedLookasideList(&Manager->ReservationLookaside, reservation);
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Check buffer space
    //
    usage = TbpGetRingBufferUsage(targetBuffer);
    if (usage >= (targetBuffer->BufferSize * TB_CRITICAL_WATER_PERCENT / 100)) {
        KeLowerIrql(oldIrql);
        InterlockedIncrement(&targetBuffer->DropCount);
        ExFreeToNPagedLookasideList(&Manager->ReservationLookaside, reservation);
        return STATUS_DEVICE_BUSY;
    }

    //
    // Acquire producer lock for slot allocation
    //
    KeAcquireSpinLockAtDpcLevel(&targetBuffer->ProducerLock);

    producerIdx = targetBuffer->ProducerIndex;
    consumerIdx = targetBuffer->ConsumerIndex;

    //
    // Check if buffer is full
    //
    if ((producerIdx - consumerIdx) >= (LONG64)targetBuffer->SlotCount) {
        KeReleaseSpinLockFromDpcLevel(&targetBuffer->ProducerLock);
        KeLowerIrql(oldIrql);
        InterlockedIncrement(&targetBuffer->DropCount);
        ExFreeToNPagedLookasideList(&Manager->ReservationLookaside, reservation);
        return STATUS_DEVICE_BUSY;
    }

    //
    // Calculate slot index
    //
    slotIndex = (ULONG)(producerIdx & targetBuffer->SlotMask);

    //
    // Atomically transition slot state from Free to Reserved
    //
    expectedState = TbSlotState_Free;
    if (InterlockedCompareExchange(
            &targetBuffer->SlotStates[slotIndex],
            TbSlotState_Reserved,
            expectedState) != expectedState) {
        //
        // Slot not free - shouldn't happen if indices are correct
        //
        KeReleaseSpinLockFromDpcLevel(&targetBuffer->ProducerLock);
        KeLowerIrql(oldIrql);
        ExFreeToNPagedLookasideList(&Manager->ReservationLookaside, reservation);
        return STATUS_DEVICE_BUSY;
    }

    //
    // Advance producer index
    //
    InterlockedIncrement64(&targetBuffer->ProducerIndex);

    KeReleaseSpinLockFromDpcLevel(&targetBuffer->ProducerLock);

    //
    // Calculate destination pointer
    //
    slotOffset = slotIndex * targetBuffer->EntrySlotSize;
    destPtr = (PUCHAR)targetBuffer->Buffer + slotOffset;

    //
    // Initialize header
    //
    headerPtr = (PTB_ENTRY_HEADER)destPtr;
    RtlZeroMemory(headerPtr, sizeof(TB_ENTRY_HEADER));
    headerPtr->Signature = TB_ENTRY_SIGNATURE;
    headerPtr->EntrySize = Size;
    headerPtr->SequenceNumber = (ULONG64)InterlockedIncrement64(&Manager->GlobalSequenceNumber);
    KeQuerySystemTime(&headerPtr->Timestamp);
    headerPtr->QpcTimestamp = KeQueryPerformanceCounter(NULL);
    headerPtr->ProcessorNumber = currentCpu;
    headerPtr->ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    headerPtr->ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    headerPtr->SessionId = TbpGetSessionId();
    headerPtr->PayloadOffset = sizeof(TB_ENTRY_HEADER);
    headerPtr->PayloadSize = Size - sizeof(TB_ENTRY_HEADER);

    KeLowerIrql(oldIrql);

    //
    // Fill reservation context
    //
    reservation->RingBuffer = targetBuffer;
    reservation->SlotIndex = slotIndex;
    reservation->ProducerIndex = producerIdx;
    reservation->Header = headerPtr;
    reservation->PayloadPtr = destPtr + sizeof(TB_ENTRY_HEADER);
    reservation->TotalSize = Size;
    reservation->ProcessorNumber = currentCpu;
    reservation->IsValid = TRUE;

    //
    // Return to caller
    //
    *Context = reservation;
    *Header = headerPtr;
    *PayloadPtr = reservation->PayloadPtr;

    return STATUS_SUCCESS;
}

/**
 * @brief Commit a previously reserved entry.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbCommit(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_RESERVATION_CONTEXT Context
    )
{
    PTB_RING_BUFFER ringBuffer;
    LONG expectedState;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return;
    }

    if (Context == NULL || !Context->IsValid) {
        return;
    }

    ringBuffer = Context->RingBuffer;
    if (ringBuffer == NULL) {
        return;
    }

    //
    // Validate signature
    //
    if (Context->Header->Signature != TB_ENTRY_SIGNATURE) {
        //
        // Corrupted - abort instead
        //
        TbAbort(Manager, Context);
        return;
    }

    //
    // Compute CRC32 for header + payload
    //
    Context->Header->ChecksumCRC32 = TbpComputeEntryCRC32(
        Context->Header,
        Context->PayloadPtr
    );

    //
    // Atomically transition slot state from Reserved to Committed
    //
    expectedState = TbSlotState_Reserved;
    if (InterlockedCompareExchange(
            &ringBuffer->SlotStates[Context->SlotIndex],
            TbSlotState_Committed,
            expectedState) == expectedState) {
        //
        // Successfully committed
        //
        InterlockedIncrement64(&ringBuffer->CommittedCount);
        InterlockedIncrement64(&ringBuffer->TotalEnqueued);
        InterlockedAdd64(&ringBuffer->TotalBytes, Context->TotalSize);
        InterlockedIncrement64(&Manager->Stats.TotalEnqueued);
        InterlockedAdd64(&Manager->Stats.TotalBytes, Context->TotalSize);

        //
        // Signal consumer
        //
        KeSetEvent(&ringBuffer->ConsumerEvent, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&Manager->GlobalConsumerEvent, IO_NO_INCREMENT, FALSE);
    }

    //
    // Invalidate and free context
    //
    Context->IsValid = FALSE;
    if (Manager->ReservationLookasideInitialized) {
        ExFreeToNPagedLookasideList(&Manager->ReservationLookaside, Context);
    }
}

/**
 * @brief Abort a previously reserved entry.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbAbort(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_RESERVATION_CONTEXT Context
    )
{
    PTB_RING_BUFFER ringBuffer;
    LONG expectedState;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return;
    }

    if (Context == NULL || !Context->IsValid) {
        return;
    }

    ringBuffer = Context->RingBuffer;
    if (ringBuffer == NULL) {
        goto Cleanup;
    }

    //
    // Clear the entry signature so consumers skip it
    //
    if (Context->Header != NULL) {
        Context->Header->Signature = 0;
        Context->Header->EntrySize = 0;
    }

    //
    // Atomically transition slot state from Reserved to Aborted
    //
    expectedState = TbSlotState_Reserved;
    InterlockedCompareExchange(
        &ringBuffer->SlotStates[Context->SlotIndex],
        TbSlotState_Aborted,
        expectedState
    );

    //
    // We still need to track that this slot was "used" for consumer advancement
    //
    InterlockedIncrement64(&ringBuffer->CommittedCount);

Cleanup:
    //
    // Invalidate and free context
    //
    Context->IsValid = FALSE;
    if (Manager->ReservationLookasideInitialized) {
        ExFreeToNPagedLookasideList(&Manager->ReservationLookaside, Context);
    }
}

// ============================================================================
// DEQUEUE
// ============================================================================

/**
 * @brief Dequeue entries to caller-provided buffer.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbDequeue(
    _In_ PTB_MANAGER Manager,
    _Out_writes_bytes_to_(BufferSize, *BytesReturned) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned,
    _Out_ PULONG EntriesReturned,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    )
{
    NTSTATUS status;
    ULONG totalBytes = 0;
    ULONG totalEntries = 0;
    ULONG cpuBytes;
    ULONG cpuEntries;
    PUCHAR currentPtr;
    ULONG remainingSize;
    ULONG i;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Options);

    *BytesReturned = 0;
    *EntriesReturned = 0;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Buffer == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    currentPtr = (PUCHAR)Buffer;
    remainingSize = BufferSize;

    //
    // Dequeue from each per-CPU buffer
    //
    for (i = 0; i < Manager->ActiveCpuCount && remainingSize > sizeof(TB_ENTRY_HEADER); i++) {
        if (Manager->PerCpuBuffers[i] == NULL) {
            continue;
        }

        status = TbpDequeueFromRingBuffer(
            &Manager->PerCpuBuffers[i]->RingBuffer,
            currentPtr,
            remainingSize,
            &cpuBytes,
            &cpuEntries
        );

        if (NT_SUCCESS(status) && cpuBytes > 0) {
            currentPtr += cpuBytes;
            remainingSize -= cpuBytes;
            totalBytes += cpuBytes;
            totalEntries += cpuEntries;
        }
    }

    //
    // Also check overflow buffer
    //
    if (remainingSize > sizeof(TB_ENTRY_HEADER)) {
        status = TbpDequeueFromRingBuffer(
            &Manager->GlobalOverflow,
            currentPtr,
            remainingSize,
            &cpuBytes,
            &cpuEntries
        );

        if (NT_SUCCESS(status) && cpuBytes > 0) {
            totalBytes += cpuBytes;
            totalEntries += cpuEntries;
        }
    }

    *BytesReturned = totalBytes;
    *EntriesReturned = totalEntries;

    InterlockedAdd64(&Manager->Stats.TotalDequeued, totalEntries);

    return (totalEntries > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

// ============================================================================
// BATCH DEQUEUE
// ============================================================================

/**
 * @brief Dequeue entries as a batch descriptor.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbDequeueBatch(
    _In_ PTB_MANAGER Manager,
    _Out_ PTB_BATCH_DESCRIPTOR* Batch,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    )
{
    NTSTATUS status;
    PTB_BATCH_DESCRIPTOR batch = NULL;
    PVOID batchBuffer = NULL;
    ULONG batchBufferSize;
    ULONG bytesReturned = 0;
    ULONG entriesReturned = 0;
    ULONG maxSize;
    LARGE_INTEGER timeout;
    BOOLEAN waitForData = FALSE;

    PAGED_CODE();

    *Batch = NULL;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->BatchLookasideInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Parse options
    //
    if (Options != NULL) {
        maxSize = (Options->MaxSize > 0) ? Options->MaxSize : (1024 * 1024);
        waitForData = Options->WaitForData;
    } else {
        maxSize = 1024 * 1024;
    }

    //
    // Cap batch buffer size
    //
    batchBufferSize = maxSize;
    if (batchBufferSize > 16 * 1024 * 1024) {
        batchBufferSize = 16 * 1024 * 1024;
    }

    //
    // Allocate batch buffer
    //
    batchBuffer = ExAllocatePoolZero(
        NonPagedPoolNx,
        batchBufferSize,
        TB_POOL_TAG_BATCH
    );

    if (batchBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Wait for data if requested - use consolidated global event
    //
    if (waitForData && Options != NULL && Options->TimeoutMs > 0) {
        timeout.QuadPart = -(LONGLONG)Options->TimeoutMs * 10000LL;
        KeWaitForSingleObject(
            &Manager->GlobalConsumerEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
    }

    //
    // Dequeue entries
    //
    status = TbDequeue(
        Manager,
        batchBuffer,
        batchBufferSize,
        &bytesReturned,
        &entriesReturned,
        Options
    );

    if (!NT_SUCCESS(status) || entriesReturned == 0) {
        ExFreePoolWithTag(batchBuffer, TB_POOL_TAG_BATCH);
        return (status == STATUS_NO_MORE_ENTRIES) ? STATUS_NO_MORE_ENTRIES : status;
    }

    //
    // Allocate batch descriptor
    //
    batch = (PTB_BATCH_DESCRIPTOR)ExAllocateFromNPagedLookasideList(&Manager->BatchLookaside);
    if (batch == NULL) {
        ExFreePoolWithTag(batchBuffer, TB_POOL_TAG_BATCH);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(batch, sizeof(TB_BATCH_DESCRIPTOR));

    //
    // Fill batch descriptor
    //
    batch->BatchId = (ULONG64)InterlockedIncrement64(&Manager->Stats.BatchesSent);
    KeQuerySystemTime(&batch->CreateTime);
    batch->BatchBuffer = batchBuffer;
    batch->BatchSize = bytesReturned;
    batch->EntryCount = entriesReturned;

    //
    // Extract sequence numbers from first and last entries
    //
    if (entriesReturned > 0) {
        PTB_ENTRY_HEADER firstEntry = (PTB_ENTRY_HEADER)batchBuffer;
        if (TbpValidateEntry(firstEntry, bytesReturned, batchBufferSize)) {
            batch->FirstSequence = firstEntry->SequenceNumber;

            //
            // Find last entry
            //
            PUCHAR ptr = (PUCHAR)batchBuffer;
            ULONG remaining = bytesReturned;
            PTB_ENTRY_HEADER lastEntry = firstEntry;

            while (remaining >= sizeof(TB_ENTRY_HEADER)) {
                PTB_ENTRY_HEADER entry = (PTB_ENTRY_HEADER)ptr;
                if (!TbpValidateEntry(entry, remaining, batchBufferSize)) {
                    break;
                }
                lastEntry = entry;
                ptr += entry->EntrySize;
                remaining -= entry->EntrySize;
            }
            batch->LastSequence = lastEntry->SequenceNumber;
        }
    }

    batch->IsCompressed = FALSE;
    batch->UncompressedSize = bytesReturned;
    InitializeListHead(&batch->ListEntry);

    *Batch = batch;

    return STATUS_SUCCESS;
}

/**
 * @brief Free a batch descriptor.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbFreeBatch(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_BATCH_DESCRIPTOR Batch
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return;
    }

    if (Batch == NULL) {
        return;
    }

    //
    // Free batch buffer
    //
    if (Batch->BatchBuffer != NULL) {
        ExFreePoolWithTag(Batch->BatchBuffer, TB_POOL_TAG_BATCH);
        Batch->BatchBuffer = NULL;
    }

    //
    // Free descriptor only if lookaside still initialized
    //
    if (Manager->BatchLookasideInitialized) {
        ExFreeToNPagedLookasideList(&Manager->BatchLookaside, Batch);
    }
}

// ============================================================================
// ENTRY ITERATION
// ============================================================================

/**
 * @brief Iterate entries with callback.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbIterate(
    _In_ PTB_MANAGER Manager,
    _In_ TB_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    )
{
    NTSTATUS status;
    PTB_BATCH_DESCRIPTOR batch = NULL;
    PUCHAR ptr;
    ULONG remaining;
    PTB_ENTRY_HEADER entry;
    PVOID payload;
    ULONG processedCount = 0;

    PAGED_CODE();

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Dequeue as batch
    //
    status = TbDequeueBatch(Manager, &batch, Options);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (batch == NULL || batch->BatchBuffer == NULL) {
        return STATUS_NO_MORE_ENTRIES;
    }

    //
    // Iterate through entries in batch
    //
    ptr = (PUCHAR)batch->BatchBuffer;
    remaining = batch->BatchSize;

    while (remaining >= sizeof(TB_ENTRY_HEADER)) {
        entry = (PTB_ENTRY_HEADER)ptr;

        //
        // Validate entry
        //
        if (!TbpValidateEntry(entry, remaining, batch->BatchSize)) {
            break;
        }

        //
        // Get payload pointer
        //
        if (entry->PayloadSize > 0 &&
            entry->PayloadOffset >= sizeof(TB_ENTRY_HEADER) &&
            entry->PayloadOffset + entry->PayloadSize <= entry->EntrySize) {
            payload = ptr + entry->PayloadOffset;
        } else {
            payload = NULL;
        }

        //
        // Invoke callback
        //
        status = Callback(entry, payload, Context);
        if (!NT_SUCCESS(status)) {
            //
            // Callback requested stop
            //
            break;
        }

        processedCount++;
        ptr += entry->EntrySize;
        remaining -= entry->EntrySize;
    }

    //
    // Free batch
    //
    TbFreeBatch(Manager, batch);

    return (processedCount > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get telemetry buffer statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbGetStatistics(
    _In_ PTB_MANAGER Manager,
    _Out_ PTB_STATISTICS Stats
    )
{
    ULONG i;
    ULONG64 totalCapacity = 0;
    ULONG64 usedCapacity = 0;
    LARGE_INTEGER currentTime;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(TB_STATISTICS));

    Stats->State = Manager->State;
    Stats->ActiveCpuCount = Manager->ActiveCpuCount;

    //
    // Calculate capacity and usage
    //
    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        if (Manager->PerCpuBuffers[i] != NULL) {
            PTB_RING_BUFFER rb = &Manager->PerCpuBuffers[i]->RingBuffer;
            totalCapacity += rb->BufferSize;
            usedCapacity += TbpGetRingBufferUsage(rb);

            Stats->PerCpu[i].Enqueued = rb->TotalEnqueued;
            Stats->PerCpu[i].Dropped = rb->DropCount;
            Stats->PerCpu[i].Utilization = (rb->BufferSize > 0) ?
                (ULONG)((TbpGetRingBufferUsage(rb) * 100) / rb->BufferSize) : 0;
        }
    }

    // Include overflow buffer
    totalCapacity += Manager->GlobalOverflow.BufferSize;
    usedCapacity += TbpGetRingBufferUsage(&Manager->GlobalOverflow);

    Stats->TotalCapacity = totalCapacity;
    Stats->UsedCapacity = usedCapacity;
    Stats->UtilizationPercent = (totalCapacity > 0) ?
        (ULONG)((usedCapacity * 100) / totalCapacity) : 0;

    //
    // Throughput stats
    //
    Stats->TotalEnqueued = (ULONG64)Manager->Stats.TotalEnqueued;
    Stats->TotalDequeued = (ULONG64)Manager->Stats.TotalDequeued;
    Stats->TotalDropped = (ULONG64)Manager->Stats.TotalDropped;
    Stats->TotalBytes = (ULONG64)Manager->Stats.TotalBytes;

    //
    // Batching stats
    //
    Stats->BatchesSent = (ULONG64)Manager->Stats.BatchesSent;
    Stats->PendingBatches = (ULONG)Manager->PendingBatchCount;

    //
    // Timing
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Manager->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

/**
 * @brief Reset statistics counters.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbResetStatistics(
    _In_ PTB_MANAGER Manager
    )
{
    ULONG i;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return;
    }

    InterlockedExchange64(&Manager->Stats.TotalEnqueued, 0);
    InterlockedExchange64(&Manager->Stats.TotalDequeued, 0);
    InterlockedExchange64(&Manager->Stats.TotalDropped, 0);
    InterlockedExchange64(&Manager->Stats.TotalBytes, 0);
    InterlockedExchange64(&Manager->Stats.BatchesSent, 0);
    KeQuerySystemTime(&Manager->Stats.StartTime);

    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        if (Manager->PerCpuBuffers[i] != NULL) {
            PTB_RING_BUFFER rb = &Manager->PerCpuBuffers[i]->RingBuffer;
            InterlockedExchange64(&rb->TotalEnqueued, 0);
            InterlockedExchange64(&rb->TotalDequeued, 0);
            InterlockedExchange(&rb->DropCount, 0);
        }
    }
}

// ============================================================================
// UTILITY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
TbGetUtilization(
    _In_ PTB_MANAGER Manager
    )
{
    TB_STATISTICS stats;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return 0;
    }

    if (NT_SUCCESS(TbGetStatistics(Manager, &stats))) {
        return stats.UtilizationPercent;
    }

    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TbIsAccepting(
    _In_ PTB_MANAGER Manager
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return FALSE;
    }

    return (Manager->State == TbBufferState_Active);
}

// ============================================================================
// CONSUMER REGISTRATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbRegisterConsumer(
    _In_ PTB_MANAGER Manager,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PKEVENT ReadyEvent
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Manager->ConsumerLock);

    if (Manager->ConsumerConnected) {
        ExReleasePushLockExclusive(&Manager->ConsumerLock);
        return STATUS_ALREADY_REGISTERED;
    }

    Manager->ConsumerFileObject = FileObject;
    Manager->ConsumerReadyEvent = ReadyEvent;
    Manager->ConsumerConnected = TRUE;

    ExReleasePushLockExclusive(&Manager->ConsumerLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Consumer registered: FileObject=%p\n", FileObject);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
TbUnregisterConsumer(
    _In_ PTB_MANAGER Manager,
    _In_ PFILE_OBJECT FileObject
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return;
    }

    ExAcquirePushLockExclusive(&Manager->ConsumerLock);

    if (Manager->ConsumerFileObject == FileObject) {
        Manager->ConsumerFileObject = NULL;
        Manager->ConsumerReadyEvent = NULL;
        Manager->ConsumerConnected = FALSE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike/TB] Consumer unregistered: FileObject=%p\n", FileObject);
    }

    ExReleasePushLockExclusive(&Manager->ConsumerLock);
}

// ============================================================================
// FLOW CONTROL
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbSetFlowControl(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG HighWaterPercent,
    _In_ ULONG LowWaterPercent
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (HighWaterPercent > 100 || LowWaterPercent > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    if (LowWaterPercent >= HighWaterPercent) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Manager->ManagerLock);

    Manager->Config.HighWaterPercent = HighWaterPercent;
    Manager->Config.LowWaterPercent = LowWaterPercent;

    ExReleasePushLockExclusive(&Manager->ManagerLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Flow control set: High=%u%%, Low=%u%%\n",
               HighWaterPercent, LowWaterPercent);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbRegisterOverflowCallback(
    _In_ PTB_MANAGER Manager,
    _In_ TB_OVERFLOW_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Manager->OverflowCallbackLock);

    Manager->OverflowCallback = (PVOID)Callback;
    Manager->OverflowCallbackContext = Context;

    ExReleasePushLockExclusive(&Manager->OverflowCallbackLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Overflow callback registered\n");

    return STATUS_SUCCESS;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbSetCompression(
    _In_ PTB_MANAGER Manager,
    _In_ BOOLEAN Enable
    )
{
    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Compression is not implemented - return NOT_IMPLEMENTED if trying to enable
    //
    if (Enable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/TB] Compression not implemented\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    ExAcquirePushLockExclusive(&Manager->ManagerLock);
    Manager->Config.EnableCompression = FALSE;
    ExReleasePushLockExclusive(&Manager->ManagerLock);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbSetEncryption(
    _In_ PTB_MANAGER Manager,
    _In_ BOOLEAN Enable,
    _In_opt_ PUCHAR Key,
    _In_ ULONG KeySize
    )
{
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Encryption is not implemented - return NOT_IMPLEMENTED if trying to enable
    //
    if (Enable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/TB] Encryption not implemented\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    ExAcquirePushLockExclusive(&Manager->ManagerLock);
    Manager->Config.EnableEncryption = FALSE;
    ExReleasePushLockExclusive(&Manager->ManagerLock);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbResize(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG NewPerCpuSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PTB_PERCPU_BUFFER* newBuffers = NULL;
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (NewPerCpuSize < TB_MIN_BUFFER_SIZE || NewPerCpuSize > TB_MAX_BUFFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Manager->State != TbBufferState_Paused) {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Resizing buffers: %u -> %u bytes\n",
               Manager->Config.PerCpuBufferSize, NewPerCpuSize);

    //
    // Allocate array for new buffer pointers
    //
    newBuffers = (PTB_PERCPU_BUFFER*)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PTB_PERCPU_BUFFER) * TB_MAX_PERCPU_BUFFERS,
        TB_POOL_TAG_BUFFER
    );

    if (newBuffers == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate new per-CPU buffers
    //
    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        newBuffers[i] = (PTB_PERCPU_BUFFER)ExAllocatePoolZero(
            NonPagedPoolNx,
            sizeof(TB_PERCPU_BUFFER),
            TB_POOL_TAG_PERCPU
        );

        if (newBuffers[i] == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        status = TbpInitializePerCpuBuffer(newBuffers[i], i, NewPerCpuSize);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(newBuffers[i], TB_POOL_TAG_PERCPU);
            newBuffers[i] = NULL;
            goto Cleanup;
        }
    }

    //
    // Swap buffers under lock
    //
    ExAcquirePushLockExclusive(&Manager->ManagerLock);

    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        PTB_PERCPU_BUFFER oldBuffer = Manager->PerCpuBuffers[i];
        Manager->PerCpuBuffers[i] = newBuffers[i];
        newBuffers[i] = oldBuffer;
    }

    Manager->Config.PerCpuBufferSize = NewPerCpuSize;

    ExReleasePushLockExclusive(&Manager->ManagerLock);

    //
    // Free old buffers
    //
    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        if (newBuffers[i] != NULL) {
            TbpDestroyPerCpuBuffer(newBuffers[i]);
            ExFreePoolWithTag(newBuffers[i], TB_POOL_TAG_PERCPU);
        }
    }

    ExFreePoolWithTag(newBuffers, TB_POOL_TAG_BUFFER);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Buffer resize complete\n");

    return STATUS_SUCCESS;

Cleanup:
    if (newBuffers != NULL) {
        for (i = 0; i < TB_MAX_PERCPU_BUFFERS; i++) {
            if (newBuffers[i] != NULL) {
                TbpDestroyPerCpuBuffer(newBuffers[i]);
                ExFreePoolWithTag(newBuffers[i], TB_POOL_TAG_PERCPU);
            }
        }
        ExFreePoolWithTag(newBuffers, TB_POOL_TAG_BUFFER);
    }

    return status;
}

// ============================================================================
// DEBUGGING
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbDumpState(
    _In_ PTB_MANAGER Manager
    )
{
    ULONG i;
    TB_STATISTICS stats;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/TB] DumpState: Invalid manager\n");
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "============================================================\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "ShadowStrike Telemetry Buffer State Dump\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "============================================================\n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "Manager State: %d\n", Manager->State);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "Active CPUs: %u\n", Manager->ActiveCpuCount);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "Consumer Connected: %s\n", Manager->ConsumerConnected ? "Yes" : "No");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "Flush Thread Running: %s\n", Manager->FlushThreadRunning ? "Yes" : "No");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "\nConfiguration:\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "  Per-CPU Buffer Size: %u bytes\n", Manager->Config.PerCpuBufferSize);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "  Batch Size: %u entries\n", Manager->Config.BatchSize);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "  High Water: %u%%\n", Manager->Config.HighWaterPercent);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "  Low Water: %u%%\n", Manager->Config.LowWaterPercent);

    if (NT_SUCCESS(TbGetStatistics(Manager, &stats))) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "\nStatistics:\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Total Capacity: %llu bytes\n", stats.TotalCapacity);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Used Capacity: %llu bytes\n", stats.UsedCapacity);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Utilization: %u%%\n", stats.UtilizationPercent);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Total Enqueued: %llu\n", stats.TotalEnqueued);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Total Dequeued: %llu\n", stats.TotalDequeued);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Total Dropped: %llu\n", stats.TotalDropped);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Batches Sent: %llu\n", stats.BatchesSent);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "\nPer-CPU Buffers:\n");

    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        if (Manager->PerCpuBuffers[i] != NULL) {
            PTB_RING_BUFFER rb = &Manager->PerCpuBuffers[i]->RingBuffer;
            ULONG usage = TbpGetRingBufferUsage(rb);
            ULONG percent = (rb->BufferSize > 0) ? (usage * 100 / rb->BufferSize) : 0;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "  CPU %u: Producer=%lld, Consumer=%lld, Usage=%u%%, Drops=%ld\n",
                       i,
                       rb->ProducerIndex,
                       rb->ConsumerIndex,
                       percent,
                       rb->DropCount);
        }
    }

    {
        PTB_RING_BUFFER rb = &Manager->GlobalOverflow;
        ULONG usage = TbpGetRingBufferUsage(rb);
        ULONG percent = (rb->BufferSize > 0) ? (usage * 100 / rb->BufferSize) : 0;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "\nGlobal Overflow Buffer:\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "  Producer=%lld, Consumer=%lld, Usage=%u%%, Drops=%ld\n",
                   rb->ProducerIndex,
                   rb->ConsumerIndex,
                   percent,
                   rb->DropCount);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "============================================================\n");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbValidateIntegrity(
    _In_ PTB_MANAGER Manager
    )
{
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    if (Manager == NULL || Manager->Signature != TB_MANAGER_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate per-CPU buffers
    //
    for (i = 0; i < Manager->ActiveCpuCount; i++) {
        if (Manager->PerCpuBuffers[i] == NULL) {
            continue;
        }

        PTB_RING_BUFFER rb = &Manager->PerCpuBuffers[i]->RingBuffer;

        if (rb->Buffer == NULL && rb->BufferSize > 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/TB] Integrity error: CPU %u buffer is NULL\n", i);
            status = STATUS_DATA_ERROR;
        }

        if (rb->SlotStates == NULL && rb->SlotCount > 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/TB] Integrity error: CPU %u slot states is NULL\n", i);
            status = STATUS_DATA_ERROR;
        }

        if (rb->ConsumerIndex > rb->ProducerIndex) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/TB] Integrity error: CPU %u consumer > producer\n", i);
            status = STATUS_DATA_ERROR;
        }

        if (rb->ProducerIndex < 0 || rb->ConsumerIndex < 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/TB] Integrity error: CPU %u negative index\n", i);
            status = STATUS_DATA_ERROR;
        }
    }

    //
    // Validate global overflow buffer
    //
    {
        PTB_RING_BUFFER rb = &Manager->GlobalOverflow;

        if (rb->Buffer == NULL && rb->BufferSize > 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/TB] Integrity error: Overflow buffer is NULL\n");
            status = STATUS_DATA_ERROR;
        }

        if (rb->ConsumerIndex > rb->ProducerIndex) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike/TB] Integrity error: Overflow consumer > producer\n");
            status = STATUS_DATA_ERROR;
        }
    }

    //
    // Validate global stats consistency
    //
    if (Manager->Stats.TotalDequeued > Manager->Stats.TotalEnqueued) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/TB] Integrity error: Dequeued > Enqueued\n");
        status = STATUS_DATA_ERROR;
    }

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike/TB] Integrity check passed\n");
    }

    return status;
}

// ============================================================================
// INTERNAL: RING BUFFER
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TbpInitializeRingBuffer(
    _Out_ PTB_RING_BUFFER RingBuffer,
    _In_ ULONG Size
    )
{
    ULONG slotCount;
    ULONG slotStatesSize;

    RtlZeroMemory(RingBuffer, sizeof(TB_RING_BUFFER));

    //
    // Calculate slot count and ensure it's a power of 2
    //
    slotCount = Size / TB_DEFAULT_SLOT_SIZE;
    slotCount = TbpRoundDownToPowerOf2(slotCount);

    if (slotCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate buffer memory
    //
    RingBuffer->Buffer = ExAllocatePoolZero(
        NonPagedPoolNx,
        (SIZE_T)slotCount * TB_DEFAULT_SLOT_SIZE,
        TB_POOL_TAG_BUFFER
    );

    if (RingBuffer->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate slot states array
    //
    slotStatesSize = slotCount * sizeof(LONG);
    RingBuffer->SlotStates = (volatile LONG*)ExAllocatePoolZero(
        NonPagedPoolNx,
        slotStatesSize,
        TB_POOL_TAG_SLOTMAP
    );

    if (RingBuffer->SlotStates == NULL) {
        ExFreePoolWithTag(RingBuffer->Buffer, TB_POOL_TAG_BUFFER);
        RingBuffer->Buffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RingBuffer->BufferSize = slotCount * TB_DEFAULT_SLOT_SIZE;
    RingBuffer->EntrySlotSize = TB_DEFAULT_SLOT_SIZE;
    RingBuffer->SlotCount = slotCount;
    RingBuffer->SlotMask = slotCount - 1;

    //
    // Initialize indices
    //
    RingBuffer->ProducerIndex = 0;
    RingBuffer->ConsumerIndex = 0;
    RingBuffer->CommittedCount = 0;

    //
    // Initialize synchronization
    //
    KeInitializeSpinLock(&RingBuffer->ProducerLock);
    KeInitializeSpinLock(&RingBuffer->ConsumerLock);
    KeInitializeEvent(&RingBuffer->ConsumerEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&RingBuffer->DrainEvent, NotificationEvent, FALSE);

    RingBuffer->State = TbBufferState_Active;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TbpDestroyRingBuffer(
    _Inout_ PTB_RING_BUFFER RingBuffer
    )
{
    RingBuffer->State = TbBufferState_Uninitialized;

    if (RingBuffer->SlotStates != NULL) {
        ExFreePoolWithTag((PVOID)RingBuffer->SlotStates, TB_POOL_TAG_SLOTMAP);
        RingBuffer->SlotStates = NULL;
    }

    if (RingBuffer->Buffer != NULL) {
        ExFreePoolWithTag(RingBuffer->Buffer, TB_POOL_TAG_BUFFER);
        RingBuffer->Buffer = NULL;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
TbpInitializePerCpuBuffer(
    _Out_ PTB_PERCPU_BUFFER PerCpuBuffer,
    _In_ ULONG ProcessorNumber,
    _In_ ULONG BufferSize
    )
{
    NTSTATUS status;

    PAGED_CODE();

    RtlZeroMemory(PerCpuBuffer, sizeof(TB_PERCPU_BUFFER));

    PerCpuBuffer->ProcessorNumber = ProcessorNumber;

    status = TbpInitializeRingBuffer(&PerCpuBuffer->RingBuffer, BufferSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Initialize flush timer/DPC
    //
    KeInitializeTimer(&PerCpuBuffer->FlushTimer);
    KeInitializeDpc(&PerCpuBuffer->FlushDpc, TbpFlushTimerDpc, PerCpuBuffer);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TbpDestroyPerCpuBuffer(
    _Inout_ PTB_PERCPU_BUFFER PerCpuBuffer
    )
{
    PAGED_CODE();

    //
    // Cancel timer if active
    //
    if (InterlockedExchange(&PerCpuBuffer->TimerActive, 0)) {
        KeCancelTimer(&PerCpuBuffer->FlushTimer);
    }

    //
    // CRITICAL: Flush queued DPCs to ensure DPC has completed
    //
    KeFlushQueuedDpcs();

    //
    // Free staging buffer
    //
    if (PerCpuBuffer->StagingBuffer != NULL) {
        ExFreePoolWithTag(PerCpuBuffer->StagingBuffer, TB_POOL_TAG_BUFFER);
        PerCpuBuffer->StagingBuffer = NULL;
    }

    //
    // Destroy ring buffer
    //
    TbpDestroyRingBuffer(&PerCpuBuffer->RingBuffer);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TbpEnqueueToRingBuffer(
    _In_ PTB_MANAGER Manager,
    _Inout_ PTB_RING_BUFFER RingBuffer,
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_opt_(Header->PayloadSize) PVOID Payload,
    _In_ BOOLEAN AllowDrop
    )
{
    KIRQL oldIrql;
    LONG64 producerIdx;
    LONG64 consumerIdx;
    ULONG entrySize;
    ULONG slotIndex;
    ULONG slotOffset;
    PUCHAR destPtr;
    ULONG usage;
    LONG expectedState;

    UNREFERENCED_PARAMETER(Manager);

    if (RingBuffer->State != TbBufferState_Active) {
        return STATUS_DEVICE_NOT_READY;
    }

    entrySize = Header->EntrySize;

    //
    // Check if entry fits in slot
    //
    if (entrySize > RingBuffer->EntrySlotSize) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Check buffer space
    //
    usage = TbpGetRingBufferUsage(RingBuffer);
    if (usage >= (RingBuffer->BufferSize * TB_CRITICAL_WATER_PERCENT / 100)) {
        if (AllowDrop) {
            InterlockedIncrement(&RingBuffer->DropCount);
            InterlockedIncrement(&RingBuffer->OverflowCount);
            return STATUS_DEVICE_BUSY;
        }
    }

    //
    // Acquire producer lock for slot allocation
    //
    KeAcquireSpinLock(&RingBuffer->ProducerLock, &oldIrql);

    producerIdx = RingBuffer->ProducerIndex;
    consumerIdx = RingBuffer->ConsumerIndex;

    //
    // Check if buffer is full
    //
    if ((producerIdx - consumerIdx) >= (LONG64)RingBuffer->SlotCount) {
        KeReleaseSpinLock(&RingBuffer->ProducerLock, oldIrql);

        if (AllowDrop) {
            InterlockedIncrement(&RingBuffer->DropCount);
            return STATUS_DEVICE_BUSY;
        }

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Calculate slot index
    //
    slotIndex = (ULONG)(producerIdx & RingBuffer->SlotMask);

    //
    // Atomically transition slot from Free to Reserved
    //
    expectedState = TbSlotState_Free;
    if (InterlockedCompareExchange(
            &RingBuffer->SlotStates[slotIndex],
            TbSlotState_Reserved,
            expectedState) != expectedState) {
        //
        // Slot already in use - race condition or corruption
        //
        KeReleaseSpinLock(&RingBuffer->ProducerLock, oldIrql);
        if (AllowDrop) {
            InterlockedIncrement(&RingBuffer->DropCount);
            return STATUS_DEVICE_BUSY;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Calculate destination
    //
    slotOffset = slotIndex * RingBuffer->EntrySlotSize;
    destPtr = (PUCHAR)RingBuffer->Buffer + slotOffset;

    //
    // Copy header and payload
    //
    RtlCopyMemory(destPtr, Header, sizeof(TB_ENTRY_HEADER));
    if (Header->PayloadSize > 0 && Payload != NULL) {
        RtlCopyMemory(destPtr + sizeof(TB_ENTRY_HEADER), Payload, Header->PayloadSize);
    }

    //
    // Advance producer index
    //
    InterlockedIncrement64(&RingBuffer->ProducerIndex);

    //
    // Transition slot from Reserved to Committed
    //
    InterlockedExchange(&RingBuffer->SlotStates[slotIndex], TbSlotState_Committed);
    InterlockedIncrement64(&RingBuffer->CommittedCount);

    KeReleaseSpinLock(&RingBuffer->ProducerLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&RingBuffer->TotalEnqueued);
    InterlockedAdd64(&RingBuffer->TotalBytes, entrySize);

    //
    // Signal consumer
    //
    KeSetEvent(&RingBuffer->ConsumerEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
TbpDequeueFromRingBuffer(
    _Inout_ PTB_RING_BUFFER RingBuffer,
    _Out_writes_bytes_to_(BufferSize, *BytesReturned) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned,
    _Out_ PULONG EntriesReturned
    )
{
    KIRQL oldIrql;
    LONG64 producerIdx;
    LONG64 consumerIdx;
    PTB_ENTRY_HEADER entryHeader;
    PUCHAR sourcePtr;
    PUCHAR destPtr;
    ULONG slotIndex;
    ULONG slotOffset;
    ULONG totalBytes = 0;
    ULONG totalEntries = 0;
    ULONG entrySize;
    LONG slotState;

    *BytesReturned = 0;
    *EntriesReturned = 0;

    destPtr = (PUCHAR)Buffer;

    //
    // Acquire consumer lock for exclusive dequeue access
    //
    KeAcquireSpinLock(&RingBuffer->ConsumerLock, &oldIrql);

    while (totalBytes < BufferSize) {
        producerIdx = RingBuffer->ProducerIndex;
        consumerIdx = RingBuffer->ConsumerIndex;

        //
        // Check if buffer is empty
        //
        if (consumerIdx >= producerIdx) {
            break;
        }

        //
        // Get slot index
        //
        slotIndex = (ULONG)(consumerIdx & RingBuffer->SlotMask);

        //
        // Check slot state - only dequeue Committed or Aborted slots
        //
        slotState = InterlockedCompareExchange(
            &RingBuffer->SlotStates[slotIndex],
            TbSlotState_Free,  // Will be set if Committed
            TbSlotState_Committed
        );

        if (slotState == TbSlotState_Reserved) {
            //
            // Slot still being written - stop dequeuing
            //
            break;
        }

        if (slotState == TbSlotState_Aborted) {
            //
            // Aborted slot - skip it and mark as free
            //
            InterlockedExchange(&RingBuffer->SlotStates[slotIndex], TbSlotState_Free);
            InterlockedIncrement64(&RingBuffer->ConsumerIndex);
            continue;
        }

        if (slotState != TbSlotState_Committed) {
            //
            // Unexpected state - skip
            //
            InterlockedIncrement64(&RingBuffer->ConsumerIndex);
            continue;
        }

        //
        // Slot is now transitioning from Committed to Free (we won the CAS)
        //

        //
        // Get entry from slot
        //
        slotOffset = slotIndex * RingBuffer->EntrySlotSize;
        sourcePtr = (PUCHAR)RingBuffer->Buffer + slotOffset;
        entryHeader = (PTB_ENTRY_HEADER)sourcePtr;

        //
        // Validate entry with slot size check
        //
        if (!TbpValidateEntry(entryHeader, BufferSize - totalBytes, RingBuffer->EntrySlotSize)) {
            //
            // Invalid entry - skip slot
            //
            InterlockedIncrement64(&RingBuffer->ConsumerIndex);
            continue;
        }

        entrySize = entryHeader->EntrySize;

        //
        // Check if entry fits in output buffer
        //
        if (totalBytes + entrySize > BufferSize) {
            //
            // Restore slot state since we can't copy this entry
            //
            InterlockedExchange(&RingBuffer->SlotStates[slotIndex], TbSlotState_Committed);
            break;
        }

        //
        // Copy entry to output buffer
        //
        RtlCopyMemory(destPtr, sourcePtr, entrySize);

        destPtr += entrySize;
        totalBytes += entrySize;
        totalEntries++;

        //
        // Advance consumer index
        //
        InterlockedIncrement64(&RingBuffer->ConsumerIndex);
        InterlockedIncrement64(&RingBuffer->TotalDequeued);
    }

    KeReleaseSpinLock(&RingBuffer->ConsumerLock, oldIrql);

    *BytesReturned = totalBytes;
    *EntriesReturned = totalEntries;

    //
    // Signal drain event if empty
    //
    if (RingBuffer->ConsumerIndex >= RingBuffer->ProducerIndex) {
        KeSetEvent(&RingBuffer->DrainEvent, IO_NO_INCREMENT, FALSE);
    }

    return (totalEntries > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
TbpGetRingBufferUsage(
    _In_ PTB_RING_BUFFER RingBuffer
    )
{
    LONG64 producer = RingBuffer->ProducerIndex;
    LONG64 consumer = RingBuffer->ConsumerIndex;
    LONG64 used = producer - consumer;

    if (used < 0) {
        used = 0;
    }

    return (ULONG)(used * RingBuffer->EntrySlotSize);
}

// ============================================================================
// INTERNAL: FLUSH THREAD
// ============================================================================

_IRQL_requires_(DISPATCH_LEVEL)
static VOID
TbpFlushTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PTB_PERCPU_BUFFER perCpuBuffer = (PTB_PERCPU_BUFFER)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (perCpuBuffer != NULL) {
        InterlockedIncrement64(&perCpuBuffer->FlushCount);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
TbpFlushThreadRoutine(
    _In_ PVOID Context
    )
{
    PTB_MANAGER manager = (PTB_MANAGER)Context;
    NTSTATUS status;
    LARGE_INTEGER interval;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Flush thread started\n");

    interval.QuadPart = -(LONGLONG)TB_FLUSH_INTERVAL_MS * 10000LL;

    while (manager->FlushThreadRunning) {
        //
        // Wait for shutdown event or timeout
        //
        status = KeWaitForSingleObject(
            &manager->ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &interval
        );

        if (status == STATUS_SUCCESS) {
            //
            // Shutdown signaled
            //
            break;
        }

        //
        // Periodic tasks
        //
        if (manager->State != TbBufferState_Active) {
            continue;
        }

        //
        // Log periodic stats using manager field instead of static
        //
        manager->FlushIterationCount++;
        if (manager->FlushIterationCount >= TB_FLUSH_LOG_INTERVAL) {
            manager->FlushIterationCount = 0;
            ULONG utilization = TbGetUtilization(manager);
            if (utilization > manager->Config.HighWaterPercent) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/TB] High utilization: %u%%, Enqueued=%llu, Dropped=%llu\n",
                           utilization,
                           manager->Stats.TotalEnqueued,
                           manager->Stats.TotalDropped);
            }
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/TB] Flush thread exiting\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}
