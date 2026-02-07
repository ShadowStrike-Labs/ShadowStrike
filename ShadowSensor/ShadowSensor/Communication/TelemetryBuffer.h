/*++
    ShadowStrike Next-Generation Antivirus
    Module: TelemetryBuffer.h
    
    Purpose: High-performance ring buffer for telemetry event collection
             and batched delivery to user-mode components.
             
    Architecture:
    - Lock-free ring buffer with producer/consumer indices
    - Per-CPU buffers to minimize contention
    - Overflow protection with event dropping statistics
    - Batch coalescing for efficient user-mode transfer
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../Shared/TelemetryTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define TB_POOL_TAG_BUFFER      'FBBT'  // Telemetry Buffer - Buffer
#define TB_POOL_TAG_ENTRY       'EBBT'  // Telemetry Buffer - Entry
#define TB_POOL_TAG_PERCPU      'PBBT'  // Telemetry Buffer - Per-CPU
#define TB_POOL_TAG_BATCH       'ABBT'  // Telemetry Buffer - Batch

//=============================================================================
// Configuration Constants
//=============================================================================

// Buffer sizes
#define TB_DEFAULT_BUFFER_SIZE          (16 * 1024 * 1024)  // 16 MB per buffer
#define TB_MIN_BUFFER_SIZE              (1 * 1024 * 1024)   // 1 MB minimum
#define TB_MAX_BUFFER_SIZE              (256 * 1024 * 1024) // 256 MB maximum
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
    ULONG ChecksumCRC32;                // CRC32 of entire entry
    
    //
    // Chaining support
    //
    ULONG64 ChainId;                    // For multi-entry events
    USHORT ChainIndex;                  // Position in chain
    USHORT ChainCount;                  // Total entries in chain
    
    ULONG Reserved;
} TB_ENTRY_HEADER, *PTB_ENTRY_HEADER;

C_ASSERT(sizeof(TB_ENTRY_HEADER) == 80);

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
    // Producer/Consumer indices (cache-line aligned)
    //
    volatile LONG64 ProducerIndex __declspec(align(64));
    volatile LONG64 ConsumerIndex __declspec(align(64));
    volatile LONG64 CommittedIndex __declspec(align(64));
    
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
    BOOLEAN TimerActive;
    
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
    // Per-CPU buffers
    //
    PTB_PERCPU_BUFFER PerCpuBuffers[TB_MAX_PERCPU_BUFFERS];
    ULONG ActiveCpuCount;
    
    //
    // Global overflow buffer (for when per-CPU is full)
    //
    TB_RING_BUFFER GlobalOverflow;
    
    //
    // Batch management
    //
    LIST_ENTRY PendingBatches;          // Batches waiting for consumer
    KSPIN_LOCK BatchListLock;
    ULONG MaxPendingBatches;
    volatile LONG PendingBatchCount;
    
    //
    // Consumer registration
    //
    PFILE_OBJECT ConsumerFileObject;    // Registered consumer
    PKEVENT ConsumerReadyEvent;         // Consumer ready to receive
    BOOLEAN ConsumerConnected;
    
    //
    // Manager state
    //
    volatile TB_BUFFER_STATE State;
    KEVENT ShutdownEvent;
    PKTHREAD FlushThread;               // Background flush thread
    BOOLEAN FlushThreadRunning;
    
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

//
// Initialize the telemetry buffer manager
//
NTSTATUS
TbInitialize(
    _Out_ PTB_MANAGER* Manager,
    _In_ ULONG PerCpuBufferSize,
    _In_ ULONG BatchSize,
    _In_ ULONG BatchTimeoutMs
    );

//
// Shutdown the telemetry buffer manager
//
VOID
TbShutdown(
    _Inout_ PTB_MANAGER Manager
    );

//
// Start/Stop buffering
//
NTSTATUS
TbStart(
    _Inout_ PTB_MANAGER Manager
    );

NTSTATUS
TbStop(
    _Inout_ PTB_MANAGER Manager,
    _In_ BOOLEAN Drain
    );

NTSTATUS
TbPause(
    _Inout_ PTB_MANAGER Manager
    );

NTSTATUS
TbResume(
    _Inout_ PTB_MANAGER Manager
    );

//=============================================================================
// Public API - Enqueueing
//=============================================================================

//
// Enqueue a telemetry entry
//
NTSTATUS
TbEnqueue(
    _In_ PTB_MANAGER Manager,
    _In_ TB_ENTRY_TYPE EntryType,
    _In_reads_bytes_(PayloadSize) PVOID Payload,
    _In_ ULONG PayloadSize,
    _In_opt_ PTB_ENQUEUE_OPTIONS Options
    );

//
// Enqueue with pre-built header
//
NTSTATUS
TbEnqueueWithHeader(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_ENTRY_HEADER Header,
    _In_reads_bytes_(Header->PayloadSize) PVOID Payload,
    _In_opt_ PTB_ENQUEUE_OPTIONS Options
    );

//
// Reserve space and enqueue in two steps (for large entries)
//
NTSTATUS
TbReserve(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG Size,
    _Out_ PTB_ENTRY_HEADER* Header,
    _Out_ PVOID* PayloadPtr
    );

VOID
TbCommit(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_ENTRY_HEADER Header
    );

VOID
TbAbort(
    _In_ PTB_MANAGER Manager,
    _In_ PTB_ENTRY_HEADER Header
    );

//=============================================================================
// Public API - Dequeueing
//=============================================================================

//
// Dequeue entries to caller-provided buffer
//
NTSTATUS
TbDequeue(
    _In_ PTB_MANAGER Manager,
    _Out_writes_bytes_to_(BufferSize, *BytesReturned) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned,
    _Out_ PULONG EntriesReturned,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    );

//
// Dequeue as batch descriptor
//
NTSTATUS
TbDequeueBatch(
    _In_ PTB_MANAGER Manager,
    _Out_ PTB_BATCH_DESCRIPTOR* Batch,
    _In_opt_ PTB_DEQUEUE_OPTIONS Options
    );

//
// Free batch descriptor
//
VOID
TbFreeBatch(
    _In_ PTB_BATCH_DESCRIPTOR Batch
    );

//
// Iterate entries with callback
//
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

//
// Register consumer for notifications
//
NTSTATUS
TbRegisterConsumer(
    _In_ PTB_MANAGER Manager,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PKEVENT ReadyEvent
    );

//
// Unregister consumer
//
VOID
TbUnregisterConsumer(
    _In_ PTB_MANAGER Manager,
    _In_ PFILE_OBJECT FileObject
    );

//=============================================================================
// Public API - Flow Control
//=============================================================================

//
// Set flow control parameters
//
NTSTATUS
TbSetFlowControl(
    _In_ PTB_MANAGER Manager,
    _In_ ULONG HighWaterPercent,
    _In_ ULONG LowWaterPercent
    );

//
// Register overflow callback
//
NTSTATUS
TbRegisterOverflowCallback(
    _In_ PTB_MANAGER Manager,
    _In_ TB_OVERFLOW_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//
// Get current buffer utilization
//
ULONG
TbGetUtilization(
    _In_ PTB_MANAGER Manager
    );

//
// Check if buffer is accepting entries
//
BOOLEAN
TbIsAccepting(
    _In_ PTB_MANAGER Manager
    );

//=============================================================================
// Public API - Configuration
//=============================================================================

//
// Enable/disable compression
//
NTSTATUS
TbSetCompression(
    _In_ PTB_MANAGER Manager,
    _In_ BOOLEAN Enable
    );

//
// Enable/disable encryption
//
NTSTATUS
TbSetEncryption(
    _In_ PTB_MANAGER Manager,
    _In_ BOOLEAN Enable,
    _In_opt_ PUCHAR Key,
    _In_ ULONG KeySize
    );

//
// Resize buffers (while paused)
//
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

NTSTATUS
TbGetStatistics(
    _In_ PTB_MANAGER Manager,
    _Out_ PTB_STATISTICS Stats
    );

VOID
TbResetStatistics(
    _In_ PTB_MANAGER Manager
    );

//=============================================================================
// Public API - Debugging
//=============================================================================

//
// Dump buffer state for debugging
//
VOID
TbDumpState(
    _In_ PTB_MANAGER Manager
    );

//
// Validate buffer integrity
//
NTSTATUS
TbValidateIntegrity(
    _In_ PTB_MANAGER Manager
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Quick enqueue for common event types
//
#define TbEnqueueProcess(Manager, Type, Payload, Size) \
    TbEnqueue(Manager, Type, Payload, Size, NULL)

#define TbEnqueueCritical(Manager, Type, Payload, Size) \
    do { \
        TB_ENQUEUE_OPTIONS _opts = { .Flags = TbFlag_Critical }; \
        TbEnqueue(Manager, Type, Payload, Size, &_opts); \
    } while (0)

#define TbEnqueueHighPriority(Manager, Type, Payload, Size) \
    do { \
        TB_ENQUEUE_OPTIONS _opts = { .Flags = TbFlag_HighPriority }; \
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
