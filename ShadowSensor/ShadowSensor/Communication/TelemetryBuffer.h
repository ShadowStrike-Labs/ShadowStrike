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
    Module: TelemetryBuffer.h

    Purpose: High-performance ring buffer for telemetry event collection
             and batched delivery to user-mode components.

    Architecture:
    - Per-CPU ring buffers with proper synchronization
    - Slot state tracking for two-phase commit
    - Overflow protection with event dropping statistics
    - Batch coalescing for efficient user-mode transfer

    IRQL Requirements:
    - TbInitialize/TbShutdown: PASSIVE_LEVEL
    - TbEnqueue: <= DISPATCH_LEVEL
    - TbDequeue: PASSIVE_LEVEL
    - TbReserve/TbCommit/TbAbort: <= DISPATCH_LEVEL

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define TB_POOL_TAG_BUFFER      'FBBT'  // Telemetry Buffer - Buffer
#define TB_POOL_TAG_ENTRY       'EBBT'  // Telemetry Buffer - Entry
#define TB_POOL_TAG_PERCPU      'PBBT'  // Telemetry Buffer - Per-CPU
#define TB_POOL_TAG_BATCH       'ABBT'  // Telemetry Buffer - Batch
#define TB_POOL_TAG_SLOTMAP     'SBBT'  // Telemetry Buffer - Slot Map
#define TB_POOL_TAG_RESERVATION 'RBBT'  // Telemetry Buffer - Reservation

//=============================================================================
// Configuration Constants
//=============================================================================

// Buffer sizes
#define TB_DEFAULT_BUFFER_SIZE          (16 * 1024 * 1024)  // 16 MB per buffer
#define TB_MIN_BUFFER_SIZE              (1 * 1024 * 1024)   // 1 MB minimum
#define TB_MAX_BUFFER_SIZE              (256 * 1024 * 1024) // 256 MB maximum
#define TB_VERIFIER_BUFFER_SIZE         (1 * 1024 * 1024)   // 1 MB under verifier
#define TB_MAX_PERCPU_BUFFERS           64                   // Max CPUs

// Entry limits
#define TB_MAX_ENTRY_SIZE               (64 * 1024)         // 64 KB max entry
#define TB_MIN_ENTRY_SIZE               32                   // Minimum entry
#define TB_ENTRY_ALIGNMENT              8                    // 8-byte alignment

// Batch settings
#define TB_DEFAULT_BATCH_SIZE           4096                 // Entries per batch
#define TB_MAX_BATCH_SIZE               16384                // Max batch size
#define TB_BATCH_TIMEOUT_MS             100                  // Flush timeout

// Flow control
#define TB_HIGH_WATER_PERCENT           80                   // Start dropping
#define TB_LOW_WATER_PERCENT            50                   // Resume accepting
#define TB_CRITICAL_WATER_PERCENT       95                   // Emergency drop

// Slot configuration
#define TB_DEFAULT_SLOT_SIZE            4096                 // Size of each slot

//=============================================================================
// Telemetry Entry Types
//=============================================================================

typedef enum _TB_ENTRY_TYPE {
    TbEntryType_Invalid = 0,

    // Process Events (1-99)
    TbEntryType_ProcessCreate = 1,
    TbEntryType_ProcessTerminate = 2,
    TbEntryType_ProcessSuspend = 3,
    TbEntryType_ProcessResume = 4,
    TbEntryType_ProcessHollow = 5,
    TbEntryType_ProcessInject = 6,
    TbEntryType_ProcessTokenChange = 7,
    TbEntryType_ProcessPrivilegeChange = 8,

    // Thread Events (100-199)
    TbEntryType_ThreadCreate = 100,
    TbEntryType_ThreadTerminate = 101,
    TbEntryType_ThreadSuspend = 102,
    TbEntryType_ThreadResume = 103,
    TbEntryType_ThreadContextChange = 104,
    TbEntryType_RemoteThread = 105,
    TbEntryType_APCQueue = 106,

    // Image Events (200-299)
    TbEntryType_ImageLoad = 200,
    TbEntryType_ImageUnload = 201,
    TbEntryType_ImageModify = 202,
    TbEntryType_ImageSignature = 203,
    TbEntryType_ReflectiveLoad = 204,

    // Memory Events (300-399)
    TbEntryType_MemoryAlloc = 300,
    TbEntryType_MemoryFree = 301,
    TbEntryType_MemoryProtect = 302,
    TbEntryType_MemoryMap = 303,
    TbEntryType_MemoryWrite = 304,
    TbEntryType_MemoryExecute = 305,
    TbEntryType_ShellcodeDetect = 306,
    TbEntryType_HeapSpray = 307,
    TbEntryType_ROPChain = 308,

    // File Events (400-499)
    TbEntryType_FileCreate = 400,
    TbEntryType_FileWrite = 401,
    TbEntryType_FileDelete = 402,
    TbEntryType_FileRename = 403,
    TbEntryType_FileSetInfo = 404,
    TbEntryType_FileExecute = 405,
    TbEntryType_FileStream = 406,

    // Registry Events (500-599)
    TbEntryType_RegKeyCreate = 500,
    TbEntryType_RegKeyDelete = 501,
    TbEntryType_RegValueSet = 502,
    TbEntryType_RegValueDelete = 503,
    TbEntryType_RegKeyRename = 504,
    TbEntryType_RegPersistence = 505,

    // Network Events (600-699)
    TbEntryType_NetConnect = 600,
    TbEntryType_NetListen = 601,
    TbEntryType_NetAccept = 602,
    TbEntryType_NetSend = 603,
    TbEntryType_NetRecv = 604,
    TbEntryType_NetDns = 605,
    TbEntryType_NetBlock = 606,
    TbEntryType_NetC2Detect = 607,

    // Syscall Events (700-799)
    TbEntryType_SyscallDirect = 700,
    TbEntryType_SyscallAnomaly = 701,
    TbEntryType_SyscallHook = 702,
    TbEntryType_HeavensGate = 703,

    // Behavioral Events (800-899)
    TbEntryType_AttackChain = 800,
    TbEntryType_MITRETechnique = 801,
    TbEntryType_ThreatScore = 802,
    TbEntryType_Anomaly = 803,
    TbEntryType_IOCMatch = 804,

    // System Events (900-999)
    TbEntryType_DriverLoad = 900,
    TbEntryType_BootConfig = 901,
    TbEntryType_TimeChange = 902,
    TbEntryType_Shutdown = 903,
    TbEntryType_SecurityEvent = 904,

    TbEntryType_Max
} TB_ENTRY_TYPE;

//=============================================================================
// Telemetry Entry Flags
//=============================================================================

typedef enum _TB_ENTRY_FLAGS {
    TbFlag_None             = 0x00000000,
    TbFlag_HighPriority     = 0x00000001,  // Bypass batch, send immediately
    TbFlag_Critical         = 0x00000002,  // Never drop this event
    TbFlag_Encrypted        = 0x00000004,  // Entry contains sensitive data
    TbFlag_Compressed       = 0x00000008,  // Entry is LZ4 compressed
    TbFlag_Continued        = 0x00000010,  // Entry continues in next slot
    TbFlag_StartChain       = 0x00000020,  // Start of event chain
    TbFlag_EndChain         = 0x00000040,  // End of event chain
    TbFlag_HasPayload       = 0x00000080,  // Variable-length payload follows
    TbFlag_RequiresAck      = 0x00000100,  // Requires user-mode acknowledgment
    TbFlag_Dropped          = 0x00000200,  // Event was dropped (stats only)
    TbFlag_Aggregated       = 0x00000400,  // Aggregated from multiple events
    TbFlag_FromCache        = 0x00000800,  // Retrieved from offline cache
} TB_ENTRY_FLAGS;

//=============================================================================
// Buffer State
//=============================================================================

typedef enum _TB_BUFFER_STATE {
    TbBufferState_Uninitialized = 0,
    TbBufferState_Initializing,
    TbBufferState_Active,
    TbBufferState_Draining,
    TbBufferState_Paused,
    TbBufferState_Overflow,
    TbBufferState_Error,
    TbBufferState_Shutdown
} TB_BUFFER_STATE;

//=============================================================================
// Slot State (for two-phase commit)
//=============================================================================

typedef enum _TB_SLOT_STATE {
    TbSlotState_Free = 0,           // Slot is available
    TbSlotState_Reserved,           // Slot reserved, data being written
    TbSlotState_Committed,          // Data written, ready for consumer
    TbSlotState_Aborted             // Reservation aborted, skip this slot
} TB_SLOT_STATE;

//=============================================================================
// Telemetry Entry Header
//=============================================================================

#pragma pack(push, 1)

typedef struct _TB_ENTRY_HEADER {
    //
    // Entry identification
    //
    ULONG Signature;                    // 'TBEH' magic
    ULONG EntrySize;                    // Total entry size including header
    ULONG64 SequenceNumber;             // Monotonic sequence number

    //
    // Timestamps
    //
    LARGE_INTEGER Timestamp;            // System time when event occurred
    LARGE_INTEGER QpcTimestamp;         // QPC for precise timing

    //
    // Entry metadata
    //
    TB_ENTRY_TYPE EntryType;            // Type of telemetry entry
    TB_ENTRY_FLAGS Flags;               // Entry flags
    ULONG ProcessorNumber;              // CPU that generated this event

    //
    // Source process/thread
    //
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG SessionId;

    //
    // Payload information
    //
    ULONG PayloadOffset;                // Offset to payload from header
    ULONG PayloadSize;                  // Size of payload
    ULONG ChecksumCRC32;                // CRC32 of header + payload

    //
    // Chaining support
    //
    ULONG64 ChainId;                    // For multi-entry events
    USHORT ChainIndex;                  // Position in chain
    USHORT ChainCount;                  // Total entries in chain

    ULONG Reserved;
} TB_ENTRY_HEADER, *PTB_ENTRY_HEADER;

C_ASSERT(sizeof(TB_ENTRY_HEADER) == 84);

#define TB_ENTRY_SIGNATURE  'HBET'

#pragma pack(pop)

//=============================================================================
// Ring Buffer Structure
//=============================================================================

typedef struct _TB_RING_BUFFER {
    //
    // Buffer memory
    //
    PVOID Buffer;                       // Actual buffer memory
    ULONG BufferSize;                   // Total buffer size
    ULONG EntrySlotSize;                // Size of each slot (power of 2)
    ULONG SlotCount;                    // Number of slots
    ULONG SlotMask;                     // Mask for slot indexing

    //
    // Slot state bitmap for two-phase commit
    //
    volatile LONG* SlotStates;          // Array of TB_SLOT_STATE per slot

    //
    // Producer/Consumer indices (cache-line aligned)
    //
    DECLSPEC_ALIGN(64) volatile LONG64 ProducerIndex;
    DECLSPEC_ALIGN(64) volatile LONG64 ConsumerIndex;
    DECLSPEC_ALIGN(64) volatile LONG64 CommittedCount;  // Number of committed slots

    //
    // Buffer state
    //
    volatile TB_BUFFER_STATE State;
    volatile LONG DropCount;            // Events dropped due to overflow
    volatile LONG OverflowCount;        // Times buffer overflowed

    //
    // Synchronization
    //
    KSPIN_LOCK ProducerLock;           // For multi-producer coordination
    KSPIN_LOCK ConsumerLock;           // For multi-consumer coordination
    KEVENT ConsumerEvent;               // Signal consumer on data
    KEVENT DrainEvent;                  // Signal when buffer drained

    //
    // Statistics
    //
    volatile LONG64 TotalEnqueued;
    volatile LONG64 TotalDequeued;
    volatile LONG64 TotalBytes;
    volatile LONG64 PeakUsage;

} TB_RING_BUFFER, *PTB_RING_BUFFER;

//=============================================================================
// Per-CPU Buffer Structure
//=============================================================================

typedef struct _TB_PERCPU_BUFFER {
    //
    // The ring buffer for this CPU
    //
    TB_RING_BUFFER RingBuffer;

    //
    // CPU identification
    //
    ULONG ProcessorNumber;
    ULONG NUMANode;

    //
    // Local staging buffer for batching
    //
    PVOID StagingBuffer;
    ULONG StagingSize;
    ULONG StagingUsed;

    //
    // Flush timer
    //
    KTIMER FlushTimer;
    KDPC FlushDpc;
    volatile LONG TimerActive;          // Interlocked access

    //
    // Statistics
    //
    volatile LONG64 LocalEnqueued;
    volatile LONG64 LocalDropped;
    volatile LONG64 FlushCount;

    //
    // Cache padding
    //
    UCHAR Padding[64];

} TB_PERCPU_BUFFER, *PTB_PERCPU_BUFFER;

//=============================================================================
// Reservation Context (for two-phase commit)
//=============================================================================

typedef struct _TB_RESERVATION_CONTEXT {
    PTB_RING_BUFFER RingBuffer;         // Which ring buffer
    ULONG SlotIndex;                    // Reserved slot index
    LONG64 ProducerIndex;               // Producer index at reservation
    PTB_ENTRY_HEADER Header;            // Pointer to header in buffer
    PVOID PayloadPtr;                   // Pointer to payload area
    ULONG TotalSize;                    // Total reserved size
    ULONG ProcessorNumber;              // CPU where reserved
    BOOLEAN IsValid;                    // Reservation valid
    UCHAR Reserved[3];
} TB_RESERVATION_CONTEXT, *PTB_RESERVATION_CONTEXT;

//=============================================================================
// Batch Descriptor
//=============================================================================

typedef struct _TB_BATCH_DESCRIPTOR {
    //
    // Batch identification
    //
    ULONG64 BatchId;                    // Unique batch ID
    LARGE_INTEGER CreateTime;           // When batch was created

    //
    // Batch contents
    //
    PVOID BatchBuffer;                  // Buffer containing entries
    ULONG BatchSize;                    // Total size of batch
    ULONG EntryCount;                   // Number of entries in batch

    //
    // Source information
    //
    ULONG SourceCPU;                    // Which CPU(s) contributed
    ULONG64 FirstSequence;              // First sequence number
    ULONG64 LastSequence;               // Last sequence number

    //
    // Compression
    //
    BOOLEAN IsCompressed;
    ULONG UncompressedSize;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} TB_BATCH_DESCRIPTOR, *PTB_BATCH_DESCRIPTOR;

//=============================================================================
// Telemetry Buffer Manager
//=============================================================================

typedef struct _TB_MANAGER {
    //
    // Signature for validation
    //
    ULONG Signature;

    //
    // Per-CPU buffers
    //
    PTB_PERCPU_BUFFER PerCpuBuffers[TB_MAX_PERCPU_BUFFERS];
    ULONG ActiveCpuCount;

    //
    // Global overflow buffer (for when per-CPU is full)
    //
    TB_RING_BUFFER GlobalOverflow;

    //
    // Consolidated consumer event (signaled by any buffer)
    //
    KEVENT GlobalConsumerEvent;

    //
    // Batch management
    //
    LIST_ENTRY PendingBatches;          // Batches waiting for consumer
    KSPIN_LOCK BatchListLock;
    ULONG MaxPendingBatches;
    volatile LONG PendingBatchCount;

    //
    // Batch lookaside list (per-manager, not global)
    //
    NPAGED_LOOKASIDE_LIST BatchLookaside;
    volatile LONG BatchLookasideInitialized;

    //
    // Reservation context lookaside
    //
    NPAGED_LOOKASIDE_LIST ReservationLookaside;
    volatile LONG ReservationLookasideInitialized;

    //
    // Global sequence number
    //
    volatile LONG64 GlobalSequenceNumber;

    //
    // Consumer registration
    //
    PFILE_OBJECT ConsumerFileObject;    // Registered consumer
    PKEVENT ConsumerReadyEvent;         // Consumer ready to receive
    BOOLEAN ConsumerConnected;
    EX_PUSH_LOCK ConsumerLock;          // Protects consumer state

    //
    // Overflow callback
    //
    PVOID OverflowCallback;             // TB_OVERFLOW_CALLBACK
    PVOID OverflowCallbackContext;
    EX_PUSH_LOCK OverflowCallbackLock;

    //
    // Manager state
    //
    volatile TB_BUFFER_STATE State;
    KEVENT ShutdownEvent;
    PKTHREAD FlushThread;               // Background flush thread
    volatile LONG FlushThreadRunning;
    volatile ULONG FlushIterationCount; // Moved from static local

    //
    // Configuration
    //
    struct {
        ULONG PerCpuBufferSize;
        ULONG BatchSize;
        ULONG BatchTimeoutMs;
        ULONG HighWaterPercent;
        ULONG LowWaterPercent;
        BOOLEAN EnableCompression;
        BOOLEAN EnableEncryption;
        BOOLEAN EnablePerCpu;
    } Config;

    //
    // Global statistics
    //
    struct {
        volatile LONG64 TotalEnqueued;
        volatile LONG64 TotalDequeued;
        volatile LONG64 TotalDropped;
        volatile LONG64 TotalBytes;
        volatile LONG64 BatchesSent;
        volatile LONG64 CompressionSaved;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Synchronization
    //
    EX_PUSH_LOCK ManagerLock;

} TB_MANAGER, *PTB_MANAGER;

#define TB_MANAGER_SIGNATURE    'BMET'

//=============================================================================
// Enqueue Options
//=============================================================================

typedef struct _TB_ENQUEUE_OPTIONS {
    TB_ENTRY_FLAGS Flags;               // Entry flags
    ULONG64 ChainId;                    // Chain ID for multi-entry events
    USHORT ChainIndex;                  // Position in chain
    USHORT ChainCount;                  // Total chain length
    BOOLEAN PreferLocal;                // Prefer local CPU buffer
    BOOLEAN AllowDrop;                  // Allow dropping if full
} TB_ENQUEUE_OPTIONS, *PTB_ENQUEUE_OPTIONS;

//=============================================================================
// Dequeue Options
//=============================================================================

typedef struct _TB_DEQUEUE_OPTIONS {
    ULONG MaxEntries;                   // Maximum entries to dequeue
    ULONG MaxSize;                      // Maximum total size
    ULONG TimeoutMs;                    // Wait timeout
    BOOLEAN WaitForData;                // Wait if no data
    BOOLEAN AsBatch;                    // Return as batch descriptor
    ULONG ProcessorMask;                // Which CPUs to drain (0 = all)
} TB_DEQUEUE_OPTIONS, *PTB_DEQUEUE_OPTIONS;

//=============================================================================
// Callback Types
//=============================================================================

typedef NTSTATUS (*TB_ENTRY_CALLBACK)(
    _In_ PTB_ENTRY_HEADER Entry,
    _In_ PVOID Payload,
    _In_opt_ PVOID Context
    );

typedef VOID (*TB_OVERFLOW_CALLBACK)(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG DropCount,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbInitialize(
    _Out_ PTB_MANAGER* Manager,
    _In_ ULONG PerCpuBufferSize,
    _In_ ULONG BatchSize,
    _In_ ULONG BatchTimeoutMs
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TbShutdown(
    _Inout_ PTB_MANAGER Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbStart(
    _Inout_ PTB_MANAGER Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbStop(
    _Inout_ PTB_MANAGER Manager,
    _In_ BOOLEAN Drain
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbPause(
    _Inout_ PTB_MANAGER Manager
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbResume(
    _Inout_ PTB_MANAGER Manager
    );

//=============================================================================
// Public API - Enqueueing
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbEnqueue(
    _In_ PTB_MANAGER Manager,
    _In_ TB_ENTRY_TYPE EntryType,
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_opt_ PTB_ENQUEUE_OPTIONS Options
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbEnqueueWithHeader(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_(Header->PayloadSize) PVOID Payload,
    _In_opt_ PTB_ENQUEUE_OPTIONS Options
    );

//=============================================================================
// Public API - Two-Phase Commit (Reserve/Commit/Abort)
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbReserve(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG Size,
    _Out_ PTB_RESERVATION_CONTEXT* Context,
    _Out_ PTB_ENTRY_HEADER* Header,
    _Out_ PVOID* PayloadPtr
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbCommit(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_RESERVATION_CONTEXT Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbAbort(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_RESERVATION_CONTEXT Context
    );

//=============================================================================
// Public API - Dequeueing
//=============================================================================

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
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbDequeueBatch(
    _In_ PTB_MANAGER Manager,
    _Out_ PTB_BATCH_DESCRIPTOR* Batch,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbFreeBatch(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_BATCH_DESCRIPTOR Batch
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbIterate(
    _In_ PTB_MANAGER Manager,
    _In_ TB_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    );

//=============================================================================
// Public API - Consumer Registration
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbRegisterConsumer(
    _In_ PTB_MANAGER Manager,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PKEVENT ReadyEvent
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
TbUnregisterConsumer(
    _In_ PTB_MANAGER Manager,
    _In_ PFILE_OBJECT FileObject
    );

//=============================================================================
// Public API - Flow Control
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbSetFlowControl(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG HighWaterPercent,
    _In_ ULONG LowWaterPercent
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbRegisterOverflowCallback(
    _In_ PTB_MANAGER Manager,
    _In_ TB_OVERFLOW_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
TbGetUtilization(
    _In_ PTB_MANAGER Manager
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
TbIsAccepting(
    _In_ PTB_MANAGER Manager
    );

//=============================================================================
// Public API - Configuration
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbSetCompression(
    _In_ PTB_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TbSetEncryption(
    _In_ PTB_MANAGER Manager,
    _In_ BOOLEAN Enable,
    _In_opt_ PUCHAR Key,
    _In_ ULONG KeySize
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TbResize(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG NewPerCpuSize
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _TB_STATISTICS {
    //
    // Buffer state
    //
    TB_BUFFER_STATE State;
    ULONG ActiveCpuCount;

    //
    // Capacity
    //
    ULONG64 TotalCapacity;
    ULONG64 UsedCapacity;
    ULONG UtilizationPercent;

    //
    // Throughput
    //
    ULONG64 TotalEnqueued;
    ULONG64 TotalDequeued;
    ULONG64 TotalDropped;
    ULONG64 TotalBytes;

    //
    // Batching
    //
    ULONG64 BatchesSent;
    ULONG PendingBatches;
    ULONG AverageBatchSize;

    //
    // Compression
    //
    ULONG64 BytesBeforeCompression;
    ULONG64 BytesAfterCompression;
    ULONG CompressionRatio;

    //
    // Timing
    //
    LARGE_INTEGER UpTime;
    ULONG64 EnqueueRatePerSec;
    ULONG64 DequeueRatePerSec;

    //
    // Per-CPU breakdown
    //
    struct {
        ULONG64 Enqueued;
        ULONG64 Dropped;
        ULONG Utilization;
    } PerCpu[TB_MAX_PERCPU_BUFFERS];

} TB_STATISTICS, *PTB_STATISTICS;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbGetStatistics(
    _In_ PTB_MANAGER Manager,
    _Out_ PTB_STATISTICS Stats
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbResetStatistics(
    _In_ PTB_MANAGER Manager
    );

//=============================================================================
// Public API - Debugging
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TbDumpState(
    _In_ PTB_MANAGER Manager
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
TbValidateIntegrity(
    _In_ PTB_MANAGER Manager
    );

//=============================================================================
// Helper Macros
//=============================================================================

#define TbEnqueueProcess(Manager, Type, Payload, Size) \
    TbEnqueue(Manager, Type, Payload, Size, NULL)

#define TbEnqueueCritical(Manager, Type, Payload, Size) \
    do { \
        TB_ENQUEUE_OPTIONS _opts = { .Flags = TbFlag_Critical, .AllowDrop = FALSE }; \
        TbEnqueue(Manager, Type, Payload, Size, &_opts); \
    } while (0)

#define TbEnqueueHighPriority(Manager, Type, Payload, Size) \
    do { \
        TB_ENQUEUE_OPTIONS _opts = { .Flags = TbFlag_HighPriority, .AllowDrop = TRUE }; \
        TbEnqueue(Manager, Type, Payload, Size, &_opts); \
    } while (0)

//=============================================================================
// Internal Functions (for unit testing)
//=============================================================================

#ifdef TB_INTERNAL_TESTING

NTSTATUS
TbRingBufferInit(
    _Out_ PTB_RING_BUFFER RingBuffer,
    _In_ ULONG Size
    );

VOID
TbRingBufferDestroy(
    _Inout_ PTB_RING_BUFFER RingBuffer
    );

NTSTATUS
TbRingBufferEnqueue(
    _Inout_ PTB_RING_BUFFER RingBuffer,
    _In_ PVOID Entry,
    _In_ ULONG Size
    );

NTSTATUS
TbRingBufferDequeue(
    _Inout_ PTB_RING_BUFFER RingBuffer,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
    );

#endif // TB_INTERNAL_TESTING

#ifdef __cplusplus
}
#endif
