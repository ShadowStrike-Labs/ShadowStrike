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
 * ShadowStrike NGAV - ENTERPRISE SCAN BRIDGE ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file ScanBridge.c
 * @brief Enterprise-grade scan bridge for kernel-to-usermode communication.
 *
 * Implements Enterprise-grade scan coordination with:
 * - Synchronous scan requests with configurable timeouts
 * - Asynchronous fire-and-forget notifications
 * - Multi-priority message queuing
 * - Connection state management
 * - Message correlation and tracking
 * - Automatic retry with exponential backoff
 * - Circuit breaker pattern for resilience
 * - Per-message statistics and latency tracking
 * - Memory-efficient buffer pooling
 * - Safe message serialization
 *
 * Security Hardened v2.1.0:
 * - All message buffers are validated before use
 * - Integer overflow protection on all size calculations
 * - Safe string handling with length limits
 * - Exception handling for user-mode data access
 * - Proper cleanup on all error paths
 * - Reference counting for thread safety
 * - Proper buffer tracking for correct deallocation
 * - Fixed initialization race conditions
 * - Proper rundown protection
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ScanBridge.h"
#include "CommPort.h"
#include "../Core/Globals.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/FileUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Behavioral/BehaviorEngine.h"
#include "../../Shared/BehaviorTypes.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Magic value for scan bridge validation
 */
#define SB_BRIDGE_MAGIC                 0x53425247  // 'SBRG'

/**
 * @brief Maximum number of pending scan requests
 */
#define SB_MAX_PENDING_REQUESTS         256

/**
 * @brief Request tracking hash bucket count
 */
#define SB_REQUEST_HASH_BUCKETS         64

/**
 * @brief Shutdown drain timeout (ms)
 */
#define SB_SHUTDOWN_DRAIN_TIMEOUT_MS    5000

/**
 * @brief Minimum time between circuit breaker state transitions (ms)
 */
#define SB_CIRCUIT_MIN_TRANSITION_MS    1000

/**
 * @brief Half-open test interval (ms)
 */
#define SB_CIRCUIT_HALF_OPEN_TEST_MS    5000

/**
 * @brief Number of verdict names in the static array
 */
#define SB_VERDICT_NAME_COUNT           6

/**
 * @brief Number of access type names in the static array
 */
#define SB_ACCESS_TYPE_NAME_COUNT       8

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Pending scan request tracking entry
 */
typedef struct _SB_PENDING_REQUEST {
    LIST_ENTRY ListEntry;           ///< Hash bucket chain
    LIST_ENTRY TimeoutEntry;        ///< Timeout queue linkage
    UINT64 MessageId;               ///< Request message ID
    KEVENT CompletionEvent;         ///< Signaled when reply arrives
    PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply; ///< Reply buffer
    PULONG ReplySize;               ///< Reply size pointer
    LARGE_INTEGER StartTime;        ///< Request start time
    LARGE_INTEGER TimeoutTime;      ///< Absolute timeout time
    volatile LONG Completed;        ///< Completion flag
    volatile LONG Cancelled;        ///< Cancellation flag
    NTSTATUS Status;                ///< Final status
} SB_PENDING_REQUEST, *PSB_PENDING_REQUEST;

/**
 * @brief Circuit breaker internal state
 */
typedef struct _SB_CIRCUIT_BREAKER {
    volatile LONG State;            ///< SB_CIRCUIT_STATE
    volatile LONG ConsecutiveFailures;
    volatile LONG ConsecutiveSuccesses;
    volatile LONG RecentTimeouts;   ///< reply-timeouts in the current window (latency trip)
    LARGE_INTEGER LastFailureTime;
    LARGE_INTEGER LastStateTransition;
    LARGE_INTEGER OpenedTime;
    LARGE_INTEGER TimeoutWindowStart; ///< start of the current reply-timeout window (100ns)
    volatile LONG64 TotalTrips;
    volatile LONG64 TotalRecoveries;
    EX_PUSH_LOCK Lock;
} SB_CIRCUIT_BREAKER, *PSB_CIRCUIT_BREAKER;

/**
 * @brief Scan bridge internal context
 */
typedef struct _SB_CONTEXT {
    //
    // Validation
    //
    ULONG Magic;
    volatile LONG Initialized;
    volatile LONG ShuttingDown;

    //
    // Message ID generation
    //
    volatile LONG64 NextMessageId;

    //
    // Lookaside lists for message buffers
    //
    NPAGED_LOOKASIDE_LIST StandardBufferLookaside;
    NPAGED_LOOKASIDE_LIST LargeBufferLookaside;
    NPAGED_LOOKASIDE_LIST RequestLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Pending request tracking
    //
    struct {
        LIST_ENTRY HashBuckets[SB_REQUEST_HASH_BUCKETS];
        LIST_ENTRY TimeoutQueue;
        KSPIN_LOCK Lock;
        volatile LONG PendingCount;
        volatile LONG PeakPending;
    } Requests;

    //
    // Circuit breaker
    //
    SB_CIRCUIT_BREAKER CircuitBreaker;

    //
    // Statistics
    //
    SB_STATISTICS Stats;

    //
    // Rundown protection for shutdown
    //
    EX_RUNDOWN_REF RundownProtection;
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;

    //
    // Push lock for configuration
    //
    EX_PUSH_LOCK ConfigLock;

} SB_CONTEXT, *PSB_CONTEXT;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global scan bridge context
 */
static SB_CONTEXT g_ScanBridge = { 0 };

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static VOID
SbpInitializeCircuitBreaker(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
);

static BOOLEAN
SbpCheckCircuitBreaker(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
);

static VOID
SbpRecordSuccess(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
);

static VOID
SbpRecordFailure(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
);

static VOID
SbpRecordTimeout(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
);

static VOID
SbpTransitionCircuitState(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker,
    _In_ SB_CIRCUIT_STATE NewState
);

static PSB_PENDING_REQUEST
SbpAllocatePendingRequest(
    VOID
);

static VOID
SbpFreePendingRequest(
    _In_ PSB_PENDING_REQUEST Request
);

static VOID
SbpAccountNotificationResult(
    _In_ NTSTATUS Status,
    _Inout_ volatile LONG64* SuccessCounter
);

static VOID
SbpUpdateLatencyStats(
    _In_ LARGE_INTEGER StartTime
);

_Must_inspect_result_
static BOOLEAN
SbpAcquireRundownProtection(
    VOID
);

static VOID
SbpReleaseRundownProtection(
    VOID
);

_Must_inspect_result_
static NTSTATUS
SbpSafeAddUlong(
    _In_ ULONG Value1,
    _In_ ULONG Value2,
    _Out_ PULONG Result
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowStrikeScanBridgeInitialize)
// Removed: #pragma alloc_text(PAGE, ShadowStrikeScanBridgeShutdown) — acquires spinlock (DISPATCH_LEVEL)
#pragma alloc_text(PAGE, SbBuildFileScanRequest)
#pragma alloc_text(PAGE, SbBuildFileScanRequestEx)
#pragma alloc_text(PAGE, SbSendScanRequest)
#pragma alloc_text(PAGE, SbSendScanRequestEx)
#pragma alloc_text(PAGE, ShadowStrikeSendProcessEvent)
#pragma alloc_text(PAGE, ShadowStrikeSendThreadNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendImageNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendRegistryNotification)
#endif

// ============================================================================
// STATIC STRING TABLES
// ============================================================================

static PCWSTR g_VerdictNames[SB_VERDICT_NAME_COUNT] = {
    L"Unknown",
    L"Clean",
    L"Malicious",
    L"Suspicious",
    L"Error",
    L"Timeout"
};

static PCWSTR g_AccessTypeNames[SB_ACCESS_TYPE_NAME_COUNT] = {
    L"None",
    L"Read",
    L"Write",
    L"Execute",
    L"Create",
    L"Rename",
    L"Delete",
    L"SetInfo"
};

// ============================================================================
// SAFE INTEGER ARITHMETIC
// ============================================================================

_Must_inspect_result_
static NTSTATUS
SbpSafeAddUlong(
    _In_ ULONG Value1,
    _In_ ULONG Value2,
    _Out_ PULONG Result
)
{
    if (Value1 > MAXULONG - Value2) {
        *Result = 0;
        return SHADOWSTRIKE_ERROR_INTEGER_OVERFLOW;
    }
    *Result = Value1 + Value2;
    return STATUS_SUCCESS;
}

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeScanBridgeInitialize(
    VOID
)
{
    ULONG i;

    PAGED_CODE();

    //
    // Zero-initialize BEFORE setting flag â€” avoids a window where
    // Initialized=1 but the struct is being cleared.
    //
    if (InterlockedCompareExchange(&g_ScanBridge.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // We own init now. Zero everything except the Initialized flag
    // which we just set. Use field-by-field zeroing to avoid clearing
    // the atomic flag and re-creating a race window.
    //
    g_ScanBridge.Magic = 0;
    g_ScanBridge.ShuttingDown = 0;
    g_ScanBridge.NextMessageId = 0;
    g_ScanBridge.LookasideInitialized = FALSE;
    g_ScanBridge.Requests.PendingCount = 0;
    g_ScanBridge.Requests.PeakPending = 0;
    g_ScanBridge.ActiveOperations = 0;
    RtlZeroMemory(&g_ScanBridge.CircuitBreaker, sizeof(SB_CIRCUIT_BREAKER));
    RtlZeroMemory(&g_ScanBridge.Stats, sizeof(SB_STATISTICS));

    //
    // Set magic value
    //
    g_ScanBridge.Magic = SB_BRIDGE_MAGIC;

    //
    // Initialize push locks
    //
    ExInitializePushLock(&g_ScanBridge.ConfigLock);
    ExInitializePushLock(&g_ScanBridge.CircuitBreaker.Lock);

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&g_ScanBridge.RundownProtection);

    //
    // Initialize pending request tracking
    //
    for (i = 0; i < SB_REQUEST_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ScanBridge.Requests.HashBuckets[i]);
    }
    InitializeListHead(&g_ScanBridge.Requests.TimeoutQueue);
    KeInitializeSpinLock(&g_ScanBridge.Requests.Lock);

    //
    // Initialize lookaside lists for message buffers
    // Note: Actual allocation size includes header for tracking
    //
    ExInitializeNPagedLookasideList(
        &g_ScanBridge.StandardBufferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SB_BUFFER_HEADER) + SB_STANDARD_BUFFER_SIZE,
        SB_MESSAGE_TAG,
        SB_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &g_ScanBridge.LargeBufferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SB_BUFFER_HEADER) + SB_LARGE_BUFFER_SIZE,
        SB_MESSAGE_TAG,
        32  // Smaller depth for large buffers
    );

    ExInitializeNPagedLookasideList(
        &g_ScanBridge.RequestLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SB_PENDING_REQUEST),
        SB_REQUEST_TAG,
        SB_MAX_PENDING_REQUESTS
    );

    g_ScanBridge.LookasideInitialized = TRUE;

    //
    // Initialize circuit breaker
    //
    SbpInitializeCircuitBreaker(&g_ScanBridge.CircuitBreaker);

    //
    // Initialize shutdown event
    //
    KeInitializeEvent(&g_ScanBridge.ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_ScanBridge.Stats.StartTime);
    g_ScanBridge.Stats.MinLatencyMs = MAXLONGLONG;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeScanBridgeShutdown(
    VOID
)
{
    KIRQL oldIrql;
    LIST_ENTRY localList;
    PLIST_ENTRY entry;
    PSB_PENDING_REQUEST request;
    ULONG i;

    // No PAGED_CODE() — acquires spinlock (DISPATCH_LEVEL).

    if (!g_ScanBridge.Initialized) {
        return;
    }

    //
    // Signal shutdown in progress
    //
    InterlockedExchange(&g_ScanBridge.ShuttingDown, 1);

    //
    // Wait for rundown protection - this blocks until all acquired refs are released
    //
    ExWaitForRundownProtectionRelease(&g_ScanBridge.RundownProtection);

    //
    // Collect all pending requests to a local list to minimize spinlock hold time
    //
    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_ScanBridge.Requests.Lock, &oldIrql);

    for (i = 0; i < SB_REQUEST_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&g_ScanBridge.Requests.HashBuckets[i])) {
            entry = RemoveHeadList(&g_ScanBridge.Requests.HashBuckets[i]);
            InsertTailList(&localList, entry);
        }
    }

    KeReleaseSpinLock(&g_ScanBridge.Requests.Lock, oldIrql);

    //
    // Now signal and free all pending requests without holding the lock
    //
    while (!IsListEmpty(&localList)) {
        entry = RemoveHeadList(&localList);
        request = CONTAINING_RECORD(entry, SB_PENDING_REQUEST, ListEntry);

        InterlockedExchange(&request->Cancelled, 1);
        request->Status = STATUS_CANCELLED;
        KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);

        //
        // Free the request structure
        //
        SbpFreePendingRequest(request);
    }

    //
    // Cleanup lookaside lists.
    //
    // CRITICAL ORDERING: clear LookasideInitialized FIRST with a memory
    // barrier so any concurrent SbAllocateMessageBuffer / SbFreeMessageBuffer
    // call (the buffer APIs are part of the public header and may be called
    // by sibling modules outside our rundown) observes the flag transition
    // before the lookaside structures are torn down. Reading lookaside as
    // valid then dispatching ExFreeToNPagedLookasideList on a deleted list
    // is a non-recoverable BSOD.
    //
    if (g_ScanBridge.LookasideInitialized) {
        g_ScanBridge.LookasideInitialized = FALSE;
        KeMemoryBarrier();
        ExDeleteNPagedLookasideList(&g_ScanBridge.StandardBufferLookaside);
        ExDeleteNPagedLookasideList(&g_ScanBridge.LargeBufferLookaside);
        ExDeleteNPagedLookasideList(&g_ScanBridge.RequestLookaside);
    }

    //
    // Clear state
    //
    g_ScanBridge.Magic = 0;
    InterlockedExchange(&g_ScanBridge.Initialized, 0);
}

// ============================================================================
// FILE SCAN OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SbBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ HANDLE RequestorProcessId,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
)
{
    PAGED_CODE();

    return SbBuildFileScanRequestEx(
        Data,
        FltObjects,
        RequestorProcessId,
        AccessType,
        NULL,  // Default options
        Request,
        RequestSize
    );
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SbBuildFileScanRequestEx(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ HANDLE RequestorProcessId,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _In_opt_ PSB_SCAN_OPTIONS Options,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PFILE_SCAN_REQUEST scanRequest = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING processName = { 0 };
    HANDLE processId = RequestorProcessId;
    ULONG totalSize = 0;
    ULONG filePathLen = 0;
    ULONG processNameLen = 0;
    PUCHAR dataPtr;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Data == NULL || FltObjects == NULL || Request == NULL || RequestSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Request = NULL;
    *RequestSize = 0;

    //
    // Validate access type
    //
    if (AccessType >= ShadowStrikeAccessMax) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if bridge is ready
    //
    if (!ShadowStrikeScanBridgeIsReady()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // BUGCHECK GUARD — MUP_FILE_SYSTEM (0x103, MUP_BUGCHECK_NO_FILECONTEXT).
    //
    // Building the request issues a synchronous information query against
    // FltObjects->FileObject (the FltQueryInformationFile(FileStandardInformation)
    // call further below). On a network / redirector volume (e.g. a VMware
    // shared folder, fronted by the Multiple UNC Provider) the target file
    // object has no MUP file context yet while we run inside the IRP_MJ_CREATE
    // pre-operation, so that query reaches mup.sys with an unrecognised file
    // object and mup!MupFsdIrpPassThrough bugchecks the box (0x103). Remote
    // files are not scanned on-access inline anyway — the serving host owns that
    // responsibility, matching the identical guard in ShadowStrikeCacheBuildKey
    // and the user-mode device-path policy — so for any network / redirector /
    // unknown filesystem we decline to build the request here. ShadowStrikePreCreate
    // only scans on an NT_SUCCESS return, so a decline fails open: the create
    // proceeds unscanned rather than crashing the system.
    //
    if (FltObjects->Instance != NULL) {
        FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN;
        NTSTATUS fsStatus = FltGetFileSystemType(FltObjects->Instance, &fsType);
        if (!NT_SUCCESS(fsStatus)     ||
            fsType == FLT_FSTYPE_MUP        ||
            fsType == FLT_FSTYPE_LANMAN     ||
            fsType == FLT_FSTYPE_RDPDR      ||
            fsType == FLT_FSTYPE_WEBDAV     ||
            fsType == FLT_FSTYPE_NFS        ||
            fsType == FLT_FSTYPE_NETWARE    ||
            fsType == FLT_FSTYPE_MS_NETWARE ||
            fsType == FLT_FSTYPE_CSVFS      ||
            fsType == FLT_FSTYPE_OPENAFS) {
            return STATUS_NOT_SUPPORTED;
        }
    }

    //
    // Acquire rundown protection
    //
    if (!SbpAcquireRundownProtection()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Get file name information.
    //
    // CACHE_ONLY (not QUERY_DEFAULT): the caller (ShadowStrikePreCreate) has
    // ALREADY queried the normalized name for this create with QUERY_DEFAULT,
    // which populates the Filter Manager name cache. Re-issuing a normalized
    // QUERY_DEFAULT here performs a SECOND filesystem name query on the same
    // in-flight IRP_MJ_CREATE; on a network/UNC path that nested query is sent
    // to mup.sys for a file object that has no MUP file context yet, which
    // bugchecks the system (0x103 MUP_FILE_SYSTEM / NO_FILECONTEXT, observed in
    // SbBuildFileScanRequestEx). CACHE_ONLY reads only the in-memory cache that
    // the caller just populated and never issues an IRP, so it cannot trigger
    // that path. On a cache miss we fall back to the OPENED name, which the
    // Filter Manager constructs from the create parameters without a filesystem
    // query.
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_CACHE_ONLY,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        //
        // Try opened name as fallback
        //
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (!NT_SUCCESS(status)) {
            SbpReleaseRundownProtection();
            return status;
        }
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        SbpReleaseRundownProtection();
        return status;
    }

    //
    // Calculate path length (with safety limit)
    //
    filePathLen = nameInfo->Name.Length;
    if (filePathLen > SB_MAX_PATH_LENGTH) {
        filePathLen = SB_MAX_PATH_LENGTH;
    }

    //
    // Resolve the operation requestor's image on a best-effort basis. A NULL
    // requestor is an explicit unknown identity, not the current worker's PID.
    //
    if (processId != NULL) {
        status = ShadowStrikeGetProcessImageName(processId, &processName);
        if (NT_SUCCESS(status) && processName.Buffer != NULL) {
            processNameLen = processName.Length;
            if (processNameLen > SB_MAX_PROCESS_NAME_LENGTH) {
                processNameLen = SB_MAX_PROCESS_NAME_LENGTH;
            }
        }
    }

    //
    // Calculate total message size with overflow protection
    //
    status = SbpSafeAddUlong(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), sizeof(FILE_SCAN_REQUEST), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = SbpSafeAddUlong(totalSize, filePathLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);  // Null terminator
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = SbpSafeAddUlong(totalSize, processNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);  // Null terminator
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Truncate path to fit within the maximum message envelope.
        // Compute the path budget as (max - fixed overhead - process name)
        // and force WCHAR alignment to avoid mid-cutting a UTF-16 code
        // unit that the user-mode service would later misparse.
        //
        ULONG fixedOverhead;
        ULONG availableForPath;
        NTSTATUS overheadStatus;

        //
        // fixedOverhead = HEADER + FILE_SCAN_REQUEST + 2 * sizeof(WCHAR)
        // (two trailing null terminators) + processNameLen.
        //
        overheadStatus = SbpSafeAddUlong(
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            sizeof(FILE_SCAN_REQUEST),
            &fixedOverhead);
        if (!NT_SUCCESS(overheadStatus)) {
            status = overheadStatus;
            goto Cleanup;
        }
        overheadStatus = SbpSafeAddUlong(fixedOverhead, 2 * sizeof(WCHAR), &fixedOverhead);
        if (!NT_SUCCESS(overheadStatus)) {
            status = overheadStatus;
            goto Cleanup;
        }
        overheadStatus = SbpSafeAddUlong(fixedOverhead, processNameLen, &fixedOverhead);
        if (!NT_SUCCESS(overheadStatus)) {
            status = overheadStatus;
            goto Cleanup;
        }

        if (fixedOverhead >= SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
            //
            // Process name and headers alone exceed envelope: we cannot
            // fit even an empty path. Fail closed rather than emit a
            // truncated/inconsistent record.
            //
            status = SHADOWSTRIKE_ERROR_MESSAGE_TOO_LARGE;
            goto Cleanup;
        }

        availableForPath = SHADOWSTRIKE_MAX_MESSAGE_SIZE - fixedOverhead;
        //
        // Round DOWN to a WCHAR boundary so the truncated path is a
        // valid UTF-16 sequence (no half code units).
        //
        availableForPath &= ~1UL;

        if (filePathLen > availableForPath) {
            filePathLen = availableForPath;
        }

        totalSize = fixedOverhead + filePathLen;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)SbAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Initialize message header
    //
    status = SbInitMessageHeader(
        header,
        ShadowStrikeMessageFileScanOnOpen,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Set flags from options if provided
    //
    if (Options != NULL) {
        if (Options->Flags & SbScanFlagHighPriority) {
            header->Flags |= SB_MSG_FLAG_HIGH_PRIORITY;
        }
        if (Options->Flags & SbScanFlagBypassCache) {
            header->Flags |= SB_MSG_FLAG_BYPASS_CACHE;
        }
    }

    //
    // Fill scan request
    //
    scanRequest = (PFILE_SCAN_REQUEST)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

    scanRequest->ProcessId = HandleToULong(processId);
    scanRequest->ThreadId = HandleToULong(PsGetCurrentThreadId());
    scanRequest->AccessType = (UINT8)AccessType;
    scanRequest->PathLength = (UINT16)filePathLen;
    scanRequest->ProcessNameLength = (UINT16)processNameLen;

    //
    // Establish a known state for the fields that are only filled
    // opportunistically below.
    //
    // These come from pool memory that is not zeroed, so leaving them unset when
    // the query fails hands user mode whatever bytes happened to be there. That
    // is not cosmetic: user mode applies a maximum-size guard, and a garbage
    // FileSize reads as an enormous file, so the scan is SKIPPED. A file whose
    // size cannot be queried would therefore go unscanned - and an attacker who
    // can make the query fail gets that for free. Zero means "unknown", which no
    // size guard rejects, so the file still gets analysed.
    //
    scanRequest->FileSize = 0;
    scanRequest->IsDirectory = 0;

    //
    // Get file attributes if available
    //
    if (FltObjects->FileObject != NULL) {
        FILE_STANDARD_INFORMATION fileInfo;
        NTSTATUS queryStatus = FltQueryInformationFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation,
            NULL
        );

        if (NT_SUCCESS(queryStatus)) {
            scanRequest->FileSize = fileInfo.EndOfFile.QuadPart;
            scanRequest->IsDirectory = fileInfo.Directory;
        }
    }

    //
    // Copy file path
    //
    dataPtr = (PUCHAR)(scanRequest + 1);

    if (filePathLen > 0 && nameInfo->Name.Buffer != NULL) {
        __try {
            RtlCopyMemory(dataPtr, nameInfo->Name.Buffer, filePathLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying file path (len=%u)\n", filePathLen);
            scanRequest->PathLength = 0;
            filePathLen = 0;
        }
        dataPtr += filePathLen;
    }

    //
    // Null terminate
    //
    *(PWCHAR)dataPtr = L'\0';
    dataPtr += sizeof(WCHAR);

    //
    // Copy process name
    //
    if (processNameLen > 0 && processName.Buffer != NULL) {
        __try {
            RtlCopyMemory(dataPtr, processName.Buffer, processNameLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying process name (len=%u)\n", processNameLen);
            scanRequest->ProcessNameLength = 0;
            processNameLen = 0;
        }
        dataPtr += processNameLen;
    }

    //
    // Null terminate
    //
    *(PWCHAR)dataPtr = L'\0';

    //
    // Success
    //
    *Request = header;
    *RequestSize = totalSize;
    status = STATUS_SUCCESS;

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_ScanBridge.Stats.TotalScanRequests);

Cleanup:
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }

    if (processName.Buffer != NULL) {
        ShadowStrikeFreeUnicodeString(&processName);
    }

    if (!NT_SUCCESS(status) && header != NULL) {
        SbFreeMessageBuffer(header);
    }

    SbpReleaseRundownProtection();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SbSendScanRequest(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_ PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
)
{
    SB_SCAN_OPTIONS options;
    SB_SCAN_RESULT result;
    NTSTATUS status;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Request == NULL || Reply == NULL || ReplySize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (*ReplySize < sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Set up options
    //
    RtlZeroMemory(&options, sizeof(options));
    options.TimeoutMs = TimeoutMs > 0 ? TimeoutMs : SB_DEFAULT_SCAN_TIMEOUT_MS;
    options.Flags = SbScanFlagSynchronous;
    options.Priority = SbPriorityNormal;
    //
    // Zero retries on the synchronous verdict-blocking create path. Every retry
    // re-runs a full FltSendMessage with the (already short) per-attempt timeout
    // plus exponential backoff, multiplying the worst-case stall on a single
    // IRP_MJ_CREATE. With fail-open policy a single bounded attempt is the
    // correct trade-off: a transient miss fails open (allows the create) rather
    // than risking a multi-second stall on a hot path that every process hits.
    //
    options.MaxRetries = 0;

    //
    // Send with extended options
    //
    status = SbSendScanRequestEx(Request, RequestSize, &options, &result);

    if (NT_SUCCESS(status)) {
        //
        // Copy result to reply
        //
        Reply->Verdict = result.Verdict;
        Reply->ResultCode = result.Status;
        Reply->ThreatDetected = result.ThreatDetected;
        Reply->ThreatScore = (UINT8)result.ThreatScore;
        Reply->CacheResult = result.FromCache;
        *ReplySize = sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY);
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SbSendScanRequestEx(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _In_opt_ PSB_SCAN_OPTIONS Options,
    _Out_ PSB_SCAN_RESULT Result
)
{
    NTSTATUS status;
    SHADOWSTRIKE_SCAN_VERDICT_REPLY reply;
    ULONG replySize;
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;
    ULONG timeoutMs;
    ULONG maxRetries;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Request == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RequestSize < sizeof(SHADOWSTRIKE_MESSAGE_HEADER) ||
        RequestSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        return SHADOWSTRIKE_ERROR_MESSAGE_TOO_LARGE;
    }

    RtlZeroMemory(Result, sizeof(SB_SCAN_RESULT));

    //
    // Check if bridge is ready
    //
    if (!ShadowStrikeScanBridgeIsReady()) {
        Result->Status = SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
        Result->Verdict = Verdict_Error;
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Acquire rundown protection
    //
    if (!SbpAcquireRundownProtection()) {
        Result->Status = STATUS_DEVICE_NOT_READY;
        Result->Verdict = Verdict_Error;
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check circuit breaker
    //
    if (!SbpCheckCircuitBreaker(&g_ScanBridge.CircuitBreaker)) {
        InterlockedIncrement64(&g_ScanBridge.Stats.FailedScans);
        SbpReleaseRundownProtection();
        Result->Status = SHADOWSTRIKE_ERROR_CIRCUIT_OPEN;
        Result->Verdict = Verdict_Error;
        return SHADOWSTRIKE_ERROR_CIRCUIT_OPEN;
    }

    //
    // Get options
    //
    if (Options != NULL) {
        timeoutMs = Options->TimeoutMs > 0 ? Options->TimeoutMs : SB_DEFAULT_SCAN_TIMEOUT_MS;
        //
        // Honor an explicit MaxRetries == 0 (no retries) rather than treating
        // zero as "unspecified". The synchronous create path deliberately
        // requests zero retries to bound its worst-case in-line stall; silently
        // promoting 0 to the default would reintroduce the multi-attempt hang.
        // The Options == NULL path below still applies the default.
        //
        maxRetries = Options->MaxRetries;
        if (maxRetries > SB_MAX_RETRY_COUNT) {
            maxRetries = SB_MAX_RETRY_COUNT;
        }
        Result->UserContext = Options->UserContext;
    } else {
        timeoutMs = SB_DEFAULT_SCAN_TIMEOUT_MS;
        maxRetries = SB_MAX_RETRY_COUNT;
    }

    //
    // Clamp timeout
    //
    if (timeoutMs < SB_MIN_SCAN_TIMEOUT_MS) {
        timeoutMs = SB_MIN_SCAN_TIMEOUT_MS;
    }
    if (timeoutMs > SB_MAX_SCAN_TIMEOUT_MS) {
        timeoutMs = SB_MAX_SCAN_TIMEOUT_MS;
    }

    //
    // Record start time
    //
    KeQuerySystemTime(&startTime);

    //
    // Send request via CommPort's ShadowStrikeSendScanRequest, which
    // handles HMAC-SHA256 authentication, pending request tracking
    // against MaxPendingRequests, and reference-counted port access.
    // ScanBridge provides the retry loop with exponential backoff.
    //
    replySize = sizeof(reply);
    RtlZeroMemory(&reply, sizeof(reply));
    status = STATUS_UNSUCCESSFUL;

    {
        ULONG attempt;
        ULONG retryDelayMs = SB_RETRY_DELAY_BASE_MS;
        LARGE_INTEGER retryInterval;

        for (attempt = 0; attempt <= maxRetries; attempt++) {
            replySize = sizeof(reply);

            status = ShadowStrikeSendScanRequest(
                Request,
                RequestSize,
                &reply,
                &replySize,
                timeoutMs
            );

            if (NT_SUCCESS(status)) {
                break;
            }

            //
            // Check if the error is retriable
            //
            if (status == STATUS_TIMEOUT ||
                status == STATUS_PORT_DISCONNECTED ||
                status == SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED ||
                status == SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED ||
                status == SHADOWSTRIKE_ERROR_QUEUE_FULL ||
                status == STATUS_DEVICE_NOT_READY) {

                if (attempt < maxRetries) {
                    InterlockedIncrement64(&g_ScanBridge.Stats.RetryCount);

                    retryInterval.QuadPart = -((LONGLONG)retryDelayMs * 10000);
                    KeDelayExecutionThread(KernelMode, FALSE, &retryInterval);

                    retryDelayMs = retryDelayMs * 2;
                    if (retryDelayMs > SB_MAX_RETRY_DELAY_MS) {
                        retryDelayMs = SB_MAX_RETRY_DELAY_MS;
                    }

                    continue;
                }
            }

            //
            // Non-retriable error or max retries exhausted
            //
            break;
        }
    }

    //
    // Record end time and calculate latency.
    // Clamp negative deltas (clock skew, system-time adjustment) to zero
    // and saturate at MAXULONG to prevent UINT32 wrap-around producing
    // bogus billion-millisecond values that would poison telemetry and
    // SLA dashboards.
    //
    KeQuerySystemTime(&endTime);
    {
        LONG64 latencyTicks = endTime.QuadPart - startTime.QuadPart;
        LONG64 latencyMs = latencyTicks > 0 ? latencyTicks / 10000 : 0;
        if (latencyMs > (LONG64)MAXULONG) {
            latencyMs = (LONG64)MAXULONG;
        }
        Result->LatencyMs = (ULONG)latencyMs;
    }

    //
    // Update statistics
    //
    SbpUpdateLatencyStats(startTime);

    if (NT_SUCCESS(status)) {
        //
        // Success - extract result
        //
        Result->Status = STATUS_SUCCESS;
        Result->Verdict = (SHADOWSTRIKE_SCAN_VERDICT)reply.Verdict;
        Result->ThreatDetected = (reply.Verdict == Verdict_Malicious ||
                                  reply.Verdict == Verdict_Suspicious);
        Result->FromCache = reply.CacheResult != 0;
        Result->ThreatScore = reply.ThreatScore;

        //
        // Log threat detections for diagnostic visibility
        //
        if (Result->ThreatDetected) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "ScanBridge: Threat detected - verdict=%ls score=%u\n",
                ShadowStrikeGetVerdictName(Result->Verdict),
                Result->ThreatScore);
        }

        //
        // Record success with circuit breaker
        //
        SbpRecordSuccess(&g_ScanBridge.CircuitBreaker);
        InterlockedIncrement64(&g_ScanBridge.Stats.SuccessfulScans);

    } else if (status == STATUS_TIMEOUT) {
        //
        // Timeout
        //
        Result->Status = SHADOWSTRIKE_ERROR_SCAN_TIMEOUT;
        Result->Verdict = Verdict_Timeout;

        //
        // Record the timeout with the circuit breaker. SbpRecordTimeout keeps
        // the consecutive-failure accounting AND applies the windowed timeout-
        // rate trip, so a connected-but-slow scanner (slow successes interleaved
        // with timeouts) still opens the breaker instead of taxing every create
        // with the full scan timeout.
        //
        SbpRecordTimeout(&g_ScanBridge.CircuitBreaker);
        InterlockedIncrement64(&g_ScanBridge.Stats.TimeoutScans);
        InterlockedIncrement64(&g_ScanBridge.Stats.FailedScans);

        BeEngineSubmitEvent(
            BehaviorEvent_ScanTimeout,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL,
            0,
            25,
            FALSE,
            NULL
        );

    } else {
        //
        // Other error (connection lost, etc.)
        //
        Result->Status = status;
        Result->Verdict = Verdict_Error;

        //
        // Record failure with circuit breaker
        //
        SbpRecordFailure(&g_ScanBridge.CircuitBreaker);
        InterlockedIncrement64(&g_ScanBridge.Stats.FailedScans);

        BeEngineSubmitEvent(
            BehaviorEvent_ScanConnectionLost,
            BehaviorCategory_Collection,
            HandleToULong(PsGetCurrentProcessId()),
            NULL,
            0,
            15,
            FALSE,
            NULL
        );
    }

    SbpReleaseRundownProtection();

    return status;
}

// ============================================================================
// NOTIFICATION OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendProcessEvent(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ BOOLEAN Create,
    _In_opt_ PUNICODE_STRING ImageName,
    _In_opt_ PUNICODE_STRING CommandLine
)
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_PROCESS_NOTIFICATION notification = NULL;
    ULONG totalSize = 0;
    ULONG imageNameLen = (ImageName != NULL && ImageName->Buffer != NULL) ? ImageName->Length : 0;
    ULONG cmdLineLen = (CommandLine != NULL && CommandLine->Buffer != NULL) ? CommandLine->Length : 0;

    PAGED_CODE();

    //
    // Check if notifications are enabled
    //
    if (!g_DriverData.Initialized || !g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Acquire rundown protection for shutdown safety
    //
    if (!SbpAcquireRundownProtection()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Cap string lengths to prevent oversized messages
    //
    if (imageNameLen > SB_MAX_PATH_LENGTH) {
        imageNameLen = SB_MAX_PATH_LENGTH;
    }
    if (cmdLineLen > SB_MAX_PATH_LENGTH) {
        cmdLineLen = SB_MAX_PATH_LENGTH;
    }

    //
    // Calculate total message size with overflow protection
    //
    status = SbpSafeAddUlong(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ProcessEventCleanup;
    }

    status = SbpSafeAddUlong(totalSize, imageNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ProcessEventCleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ProcessEventCleanup;
    }

    status = SbpSafeAddUlong(totalSize, cmdLineLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ProcessEventCleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ProcessEventCleanup;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Clamp to max and adjust string lengths to match available space
        //
        ULONG fixedOverhead = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                              sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) +
                              2 * sizeof(WCHAR);
        ULONG available = (SHADOWSTRIKE_MAX_MESSAGE_SIZE > fixedOverhead) ?
                          SHADOWSTRIKE_MAX_MESSAGE_SIZE - fixedOverhead : 0;

        if (imageNameLen > available) {
            imageNameLen = available & ~1UL;
        }
        available -= imageNameLen;
        if (cmdLineLen > available) {
            cmdLineLen = available & ~1UL;
        }
        totalSize = fixedOverhead + imageNameLen + cmdLineLen;
    }

    //
    // Allocate message buffer from lookaside list
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)SbAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ProcessEventCleanup;
    }

    //
    // Initialize header
    //
    status = SbInitMessageHeader(
        header,
        ShadowStrikeMessageProcessNotify,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        goto ProcessEventCleanup;
    }

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ParentProcessId = HandleToULong(ParentId);
    notification->CreatingProcessId = HandleToULong(PsGetCurrentProcessId());
    notification->CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    notification->Create = Create;
    notification->ImagePathLength = (UINT16)imageNameLen;
    notification->CommandLineLength = (UINT16)cmdLineLen;

    //
    // Copy variable-length strings
    //
    PUCHAR stringPtr = (PUCHAR)(notification + 1);
    ULONG remaining = totalSize - (ULONG)((PUCHAR)stringPtr - (PUCHAR)header);

    if (ImageName != NULL && ImageName->Buffer != NULL && imageNameLen > 0 && remaining >= imageNameLen) {
        __try {
            RtlCopyMemory(stringPtr, ImageName->Buffer, imageNameLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying image path (len=%u)\n", imageNameLen);
            notification->ImagePathLength = 0;
            imageNameLen = 0;
        }
        stringPtr += imageNameLen;
        remaining -= imageNameLen;
    }

    if (CommandLine != NULL && CommandLine->Buffer != NULL && cmdLineLen > 0 && remaining >= cmdLineLen) {
        __try {
            RtlCopyMemory(stringPtr, CommandLine->Buffer, cmdLineLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying command line (len=%u)\n", cmdLineLen);
            notification->CommandLineLength = 0;
        }
    }

    //
    // Send fire-and-forget notification (no reply expected)
    //
    status = ShadowStrikeSendNotification(header, totalSize);

    //
    // Account for the outcome. A refused notification is counted, not ignored.
    //
    SbpAccountNotificationResult(status, &g_ScanBridge.Stats.ProcessNotifications);

ProcessEventCleanup:
    if (header != NULL) {
        SbFreeMessageBuffer(header);
    }
    SbpReleaseRundownProtection();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendThreadNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create,
    _In_ BOOLEAN IsRemote
)
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_THREAD_NOTIFICATION notification = NULL;
    ULONG totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                      sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION);

    PAGED_CODE();

    //
    // Create is available for future use when the notification struct
    // is extended to distinguish thread creation vs termination.
    //
    UNREFERENCED_PARAMETER(Create);

    //
    // Check if notifications are enabled
    //
    if (!g_DriverData.Initialized || !g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Acquire rundown protection for shutdown safety
    //
    if (!SbpAcquireRundownProtection()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)SbAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ThreadCleanup;
    }

    //
    // Initialize header
    //
    status = SbInitMessageHeader(
        header,
        ShadowStrikeMessageThreadNotify,
        sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION)
    );

    if (!NT_SUCCESS(status)) {
        goto ThreadCleanup;
    }

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_THREAD_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ThreadId = HandleToULong(ThreadId);
    notification->CreatorProcessId = HandleToULong(PsGetCurrentProcessId());
    notification->CreatorThreadId = HandleToULong(PsGetCurrentThreadId());
    notification->IsRemote = IsRemote;

    //
    // Send notification
    //
    status = ShadowStrikeSendNotification(header, totalSize);

    //
    // Account for the outcome. A refused notification is counted, not ignored.
    //
    SbpAccountNotificationResult(status, &g_ScanBridge.Stats.ThreadNotifications);

ThreadCleanup:
    if (header != NULL) {
        SbFreeMessageBuffer(header);
    }
    SbpReleaseRundownProtection();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendImageNotification(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
)
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_IMAGE_NOTIFICATION notification = NULL;
    ULONG imageNameLen = 0;
    ULONG totalSize = 0;

    PAGED_CODE();

    //
    // Validate ImageInfo - this is required
    //
    if (ImageInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if notifications are enabled
    //
    if (!g_DriverData.Initialized || !g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Acquire rundown protection for shutdown safety
    //
    if (!SbpAcquireRundownProtection()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Get image name length with safety cap
    //
    if (FullImageName != NULL && FullImageName->Buffer != NULL) {
        imageNameLen = FullImageName->Length;
        if (imageNameLen > SB_MAX_PATH_LENGTH) {
            imageNameLen = SB_MAX_PATH_LENGTH;
        }
    }

    //
    // Calculate size with overflow protection
    //
    status = SbpSafeAddUlong(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), sizeof(SHADOWSTRIKE_IMAGE_NOTIFICATION), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ImageCleanup;
    }

    status = SbpSafeAddUlong(totalSize, imageNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ImageCleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto ImageCleanup;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Clamp to max and adjust image name length
        //
        ULONG fixedOverhead = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                              sizeof(SHADOWSTRIKE_IMAGE_NOTIFICATION) +
                              sizeof(WCHAR);
        ULONG available = (SHADOWSTRIKE_MAX_MESSAGE_SIZE > fixedOverhead) ?
                          SHADOWSTRIKE_MAX_MESSAGE_SIZE - fixedOverhead : 0;
        if (imageNameLen > available) {
            imageNameLen = available & ~1UL;
        }
        totalSize = fixedOverhead + imageNameLen;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)SbAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ImageCleanup;
    }

    //
    // Initialize header
    //
    status = SbInitMessageHeader(
        header,
        ShadowStrikeMessageImageLoad,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        goto ImageCleanup;
    }

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_IMAGE_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ImageBase = (UINT64)ImageInfo->ImageBase;
    notification->ImageSize = (UINT64)ImageInfo->ImageSize;
    notification->IsSystemImage = (ImageInfo->SystemModeImage != 0);

    //
    // Get signature information from extended info if available
    //
    if (ImageInfo->ExtendedInfoPresent) {
        //
        // ImageSignatureLevel and ImageSignatureType are bit fields on
        // IMAGE_INFO itself (available when ExtendedInfoPresent is set).
        //
        notification->SignatureLevel = (UINT8)ImageInfo->ImageSignatureLevel;
        notification->SignatureType = (UINT8)ImageInfo->ImageSignatureType;
    } else {
        notification->SignatureLevel = 0;
        notification->SignatureType = 0;
    }

    notification->ImageNameLength = (UINT16)imageNameLen;

    //
    // Copy image name
    //
    PUCHAR stringPtr = (PUCHAR)(notification + 1);
    if (FullImageName != NULL && FullImageName->Buffer != NULL && imageNameLen > 0) {
        __try {
            RtlCopyMemory(stringPtr, FullImageName->Buffer, imageNameLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying full image name (len=%u)\n", imageNameLen);
            notification->ImageNameLength = 0;
        }
    }

    //
    // Send notification
    //
    status = ShadowStrikeSendNotification(header, totalSize);

    //
    // Account for the outcome. A refused notification is counted, not ignored.
    //
    SbpAccountNotificationResult(status, &g_ScanBridge.Stats.ImageNotifications);

ImageCleanup:
    if (header != NULL) {
        SbFreeMessageBuffer(header);
    }
    SbpReleaseRundownProtection();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendRegistryNotification(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ UINT8 Operation,
    _In_opt_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
)
{
    NTSTATUS status;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_REGISTRY_NOTIFICATION notification = NULL;
    ULONG keyPathLen = (KeyPath != NULL && KeyPath->Buffer != NULL) ? KeyPath->Length : 0;
    ULONG valueNameLen = (ValueName != NULL && ValueName->Buffer != NULL) ? ValueName->Length : 0;
    ULONG totalSize = 0;

    PAGED_CODE();

    //
    // Check if notifications are enabled
    //
    if (!g_DriverData.Initialized || !g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Check if user-mode is connected
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Acquire rundown protection for shutdown safety
    //
    if (!SbpAcquireRundownProtection()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Cap string and data lengths
    //
    if (keyPathLen > SB_MAX_PATH_LENGTH) {
        keyPathLen = SB_MAX_PATH_LENGTH;
    }
    if (valueNameLen > SB_MAX_PATH_LENGTH) {
        valueNameLen = SB_MAX_PATH_LENGTH;
    }

    //
    // Limit captured data size to prevent huge messages
    //
    ULONG safeDataSize = (Data != NULL && DataSize > 0) ? DataSize : 0;
    if (safeDataSize > SB_MAX_REGISTRY_DATA_SIZE) {
        safeDataSize = SB_MAX_REGISTRY_DATA_SIZE;
    }

    //
    // Calculate size with overflow protection
    //
    status = SbpSafeAddUlong(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    status = SbpSafeAddUlong(totalSize, keyPathLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    status = SbpSafeAddUlong(totalSize, valueNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    status = SbpSafeAddUlong(totalSize, safeDataSize, &totalSize);
    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Clamp to max and adjust variable-length fields
        //
        ULONG fixedOverhead = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
                              sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION) +
                              2 * sizeof(WCHAR);
        ULONG available = (SHADOWSTRIKE_MAX_MESSAGE_SIZE > fixedOverhead) ?
                          SHADOWSTRIKE_MAX_MESSAGE_SIZE - fixedOverhead : 0;

        if (keyPathLen > available) {
            keyPathLen = available & ~1UL;
        }
        available -= keyPathLen;
        if (valueNameLen > available) {
            valueNameLen = available & ~1UL;
        }
        available -= valueNameLen;
        if (safeDataSize > available) {
            safeDataSize = available;
        }
        totalSize = fixedOverhead + keyPathLen + valueNameLen + safeDataSize;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)SbAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto RegistryCleanup;
    }

    //
    // Initialize header
    //
    status = SbInitMessageHeader(
        header,
        ShadowStrikeMessageRegistryNotify,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        goto RegistryCleanup;
    }

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_REGISTRY_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ThreadId = HandleToULong(ThreadId);
    notification->Operation = Operation;
    notification->KeyPathLength = (UINT16)keyPathLen;
    notification->ValueNameLength = (UINT16)valueNameLen;
    notification->DataSize = safeDataSize;
    notification->DataType = DataType;

    //
    // Copy variable-length data
    //
    PUCHAR stringPtr = (PUCHAR)(notification + 1);
    ULONG remaining = totalSize - (ULONG)((PUCHAR)stringPtr - (PUCHAR)header);

    // Copy key path
    if (KeyPath != NULL && KeyPath->Buffer != NULL && keyPathLen > 0 && remaining >= keyPathLen) {
        __try {
            RtlCopyMemory(stringPtr, KeyPath->Buffer, keyPathLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying registry key path (len=%u)\n", keyPathLen);
            notification->KeyPathLength = 0;
            keyPathLen = 0;
        }
        stringPtr += keyPathLen;
        remaining -= keyPathLen;
    }

    // Copy value name
    if (ValueName != NULL && ValueName->Buffer != NULL && valueNameLen > 0 && remaining >= valueNameLen) {
        __try {
            RtlCopyMemory(stringPtr, ValueName->Buffer, valueNameLen);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying value name (len=%u)\n", valueNameLen);
            notification->ValueNameLength = 0;
            valueNameLen = 0;
        }
        stringPtr += valueNameLen;
        remaining -= valueNameLen;
    }

    // Copy data (with exception handling for potentially invalid pointers)
    if (Data != NULL && safeDataSize > 0 && remaining >= safeDataSize) {
        __try {
            RtlCopyMemory(stringPtr, Data, safeDataSize);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/SB] Exception copying registry data (size=%u)\n", safeDataSize);
            RtlZeroMemory(stringPtr, safeDataSize);
            notification->DataSize = 0;
        }
    }

    //
    // Send notification
    //
    status = ShadowStrikeSendNotification(header, totalSize);

    //
    // Account for the outcome. A refused notification is counted, not ignored.
    //
    SbpAccountNotificationResult(status, &g_ScanBridge.Stats.RegistryNotifications);

RegistryCleanup:
    if (header != NULL) {
        SbFreeMessageBuffer(header);
    }
    SbpReleaseRundownProtection();

    return status;
}

// ============================================================================
// GENERIC MESSAGE OPERATIONS - REMOVED, DELIBERATELY
// ============================================================================
//
// ShadowStrikeSendMessage, ShadowStrikeSendMessageEx and SbpSendWithRetry used to
// live here. They were this driver's only unencrypted transport to user mode: the
// caller's buffer reached FltSendMessage verbatim, with no
// SHADOWSTRIKE_MSG_FLAG_ENCRYPTED and no HMAC, so the receiver had no way to bind
// the frame to the authenticated session. Measured before removal: this file
// contained zero occurrences of EncEncrypt, EncGetEncryptedSize,
// ShadowStrikePrepareEncryptedMessageHeader, g_ClientSessionEncKeys and
// SHADOWSTRIKE_MSG_FLAG_ENCRYPTED.
//
// Their only callers were the four notification senders above, which now use
// ShadowStrikeSendNotification (CommPort.c). That funnel encrypts with the
// per-session key, uses the message header as AAD, and returns
// STATUS_ENCRYPTION_FAILED rather than sending plaintext - the same policy the
// scan-request and queue-drain paths already followed.
//
// Two further defects went with them, both more costly day to day than the
// missing encryption:
//
//   1. BLOCKING. ShadowStrikeSendMessage mapped a NULL Timeout onto
//      SB_DEFAULT_SCAN_TIMEOUT_MS (30 s) with SB_MAX_RETRY_COUNT (3) retries and
//      exponential backoff. FltSendMessage waits for DELIVERY whether or not a
//      reply buffer is supplied - the reply buffer governs only a SECOND wait -
//      so each of these documented "fire-and-forget" notifications could park its
//      calling thread for up to 30 s per attempt whenever user mode was not
//      sitting in FilterGetMessage. The callers are the process, thread,
//      image-load and registry callbacks. Every genuine fire-and-forget path in
//      CommPort.c passes a zero timeout for exactly this reason, and this file's
//      own comment about non-scanner ports "which never reply, blocking
//      FltSendMessage for the full timeout budget ... and freezing the system"
//      records the hazard in the product's own words.
//
//   2. PORT SELECTION. SbpSendWithRetry acquired the port with AllowFallback ==
//      FALSE, documented in place as "scan transport". That is the right policy
//      for a verdict-blocking scan and the wrong one for telemetry, which should
//      reach any verified client and otherwise buffer in MessageQueue across the
//      reconnect window. These notifications were instead dropped outright
//      whenever the primary scanner slot was momentarily unavailable.
//
// Deleted rather than left in place behind a warning comment. A callerless public
// API that sends unauthenticated frames is an invitation to reintroduce precisely
// this: PreSetInfo.c reached this one by hand-copying its declaration instead of
// including a header, which is how a bare payload came to be framed as a message
// (409a978e). The strongest guarantee that the wrong transport is not chosen again
// is that it no longer exists.
//
// If ScanBridge ever needs a synchronous request/reply again, the encrypting path
// is ShadowStrikeSendScanRequest in CommPort.c.
//

// ============================================================================
// BUFFER MANAGEMENT
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Ret_maybenull_
PVOID
SbAllocateMessageBuffer(
    _In_ ULONG Size
)
{
    PSB_BUFFER_HEADER bufferHeader = NULL;
    ULONG totalSize;
    ULONG source;

    //
    // Validate size
    //
    if (Size == 0 || Size > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        return NULL;
    }

    //
    // Calculate total size including header (with overflow check)
    //
    if (Size > MAXULONG - sizeof(SB_BUFFER_HEADER)) {
        return NULL;
    }
    totalSize = sizeof(SB_BUFFER_HEADER) + Size;

    //
    // Check if initialized
    //
    if (!g_ScanBridge.LookasideInitialized) {
        //
        // Fallback to direct pool allocation
        //
        bufferHeader = (PSB_BUFFER_HEADER)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            totalSize,
            SB_MESSAGE_TAG
        );
        source = SB_BUFFER_SOURCE_POOL;
    } else {
        //
        // Choose appropriate lookaside based on size
        //
        if (Size <= SB_STANDARD_BUFFER_SIZE) {
            bufferHeader = (PSB_BUFFER_HEADER)ExAllocateFromNPagedLookasideList(
                &g_ScanBridge.StandardBufferLookaside
            );
            source = SB_BUFFER_SOURCE_STANDARD_LOOKASIDE;
            totalSize = sizeof(SB_BUFFER_HEADER) + SB_STANDARD_BUFFER_SIZE;
        } else {
            bufferHeader = (PSB_BUFFER_HEADER)ExAllocateFromNPagedLookasideList(
                &g_ScanBridge.LargeBufferLookaside
            );
            source = SB_BUFFER_SOURCE_LARGE_LOOKASIDE;
            totalSize = sizeof(SB_BUFFER_HEADER) + SB_LARGE_BUFFER_SIZE;
        }

        //
        // Fallback to pool if lookaside is exhausted
        //
        if (bufferHeader == NULL) {
            totalSize = sizeof(SB_BUFFER_HEADER) + Size;
            bufferHeader = (PSB_BUFFER_HEADER)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                totalSize,
                SB_MESSAGE_TAG
            );
            source = SB_BUFFER_SOURCE_POOL;
        }
    }

    if (bufferHeader == NULL) {
        return NULL;
    }

    //
    // Zero the buffer
    //
    RtlZeroMemory(bufferHeader, totalSize);

    //
    // Initialize header for tracking
    //
    bufferHeader->Magic = SB_BUFFER_HEADER_MAGIC;
    bufferHeader->Source = source;
    bufferHeader->RequestedSize = Size;
    bufferHeader->AllocatedSize = totalSize - sizeof(SB_BUFFER_HEADER);

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_ScanBridge.Stats.BuffersAllocated);
    LONG current = InterlockedIncrement(&g_ScanBridge.Stats.CurrentBuffersInUse);

    //
    // Update peak (lock-free)
    //
    LONG peak = g_ScanBridge.Stats.PeakBuffersInUse;
    while (current > peak) {
        if (InterlockedCompareExchange(&g_ScanBridge.Stats.PeakBuffersInUse, current, peak) == peak) {
            break;
        }
        peak = g_ScanBridge.Stats.PeakBuffersInUse;
    }

    //
    // Return pointer past header
    //
    return (PVOID)(bufferHeader + 1);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SbFreeMessageBuffer(
    _In_opt_ PVOID Buffer
)
{
    PSB_BUFFER_HEADER bufferHeader;

    if (Buffer == NULL) {
        return;
    }

    //
    // Get header from buffer pointer
    //
    bufferHeader = ((PSB_BUFFER_HEADER)Buffer) - 1;

    //
    // Validate header
    //
    if (bufferHeader->Magic != SB_BUFFER_HEADER_MAGIC) {
        //
        // Invalid buffer - possible corruption or double-free
        // Log error but don't crash
        //
        return;
    }

    //
    // Clear magic to detect double-free
    //
    bufferHeader->Magic = 0;

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_ScanBridge.Stats.BuffersFreed);
    InterlockedDecrement(&g_ScanBridge.Stats.CurrentBuffersInUse);

    //
    // Free to appropriate source
    //
    if (!g_ScanBridge.LookasideInitialized) {
        //
        // Lookaside not available, must be pool
        //
        ShadowStrikeFreePoolWithTag(bufferHeader, SB_MESSAGE_TAG);
    } else {
        switch (bufferHeader->Source) {
            case SB_BUFFER_SOURCE_STANDARD_LOOKASIDE:
                ExFreeToNPagedLookasideList(&g_ScanBridge.StandardBufferLookaside, bufferHeader);
                break;

            case SB_BUFFER_SOURCE_LARGE_LOOKASIDE:
                ExFreeToNPagedLookasideList(&g_ScanBridge.LargeBufferLookaside, bufferHeader);
                break;

            case SB_BUFFER_SOURCE_POOL:
            default:
                ShadowStrikeFreePoolWithTag(bufferHeader, SB_MESSAGE_TAG);
                break;
        }
    }
}

// ============================================================================
// MESSAGE CONSTRUCTION HELPERS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SbInitMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header,
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ ULONG DataSize
)
{
    LARGE_INTEGER timestamp;

    if (Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Header, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = (UINT16)MessageType;
    Header->MessageId = ShadowStrikeGenerateMessageId();
    Header->DataSize = DataSize;
    Header->TotalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + DataSize;
    Header->Flags = 0;

    KeQuerySystemTime(&timestamp);
    Header->Timestamp = timestamp.QuadPart;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
ShadowStrikeGenerateMessageId(
    VOID
)
{
    return (UINT64)InterlockedIncrement64(&g_ScanBridge.NextMessageId);
}

// ============================================================================
// CONNECTION STATE
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeScanBridgeIsReady(
    VOID
)
{
    if (!g_ScanBridge.Initialized || g_ScanBridge.ShuttingDown) {
        return FALSE;
    }

    //
    // Gate on a key-exchange-complete PRIMARY SCANNER, not merely on "any client
    // connected". During service start-up the bootstrap gate / UI / tray clients
    // connect before (or instead of) the scanner; keying readiness on the raw
    // connected-client count let synchronous file-create scans route to those
    // non-scanner ports, which never reply, blocking FltSendMessage for the full
    // timeout budget on every create and freezing the system. With this gate the
    // scan path stays fail-open until a real scanner can actually answer.
    //
    return ShadowStrikeIsPrimaryScannerConnected();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
SB_CIRCUIT_STATE
ShadowStrikeGetCircuitState(
    VOID
)
{
    if (!g_ScanBridge.Initialized) {
        return SbCircuitOpen;
    }

    return (SB_CIRCUIT_STATE)g_ScanBridge.CircuitBreaker.State;
}

// ============================================================================
// STATISTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetScanBridgeStatistics(
    _Out_ PSB_STATISTICS Stats
)
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Copy statistics snapshot
    //
    RtlCopyMemory(Stats, &g_ScanBridge.Stats, sizeof(SB_STATISTICS));

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetScanBridgeStatistics(
    VOID
)
{
    //
    // Reset counters but preserve start time
    //
    InterlockedExchange64(&g_ScanBridge.Stats.TotalScanRequests, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.SuccessfulScans, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.FailedScans, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.TimeoutScans, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.CachedResults, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.ProcessNotifications, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.ThreadNotifications, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.ImageNotifications, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.RegistryNotifications, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.TotalLatencyMs, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.MinLatencyMs, MAXLONGLONG);
    InterlockedExchange64(&g_ScanBridge.Stats.MaxLatencyMs, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.ConnectionErrors, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.MessageErrors, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.RetryCount, 0);
    InterlockedExchange(&g_ScanBridge.Stats.CircuitBreakerTrips, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.BuffersAllocated, 0);
    InterlockedExchange64(&g_ScanBridge.Stats.BuffersFreed, 0);

    KeQuerySystemTime(&g_ScanBridge.Stats.StartTime);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

PCWSTR
ShadowStrikeGetVerdictName(
    _In_ SHADOWSTRIKE_SCAN_VERDICT Verdict
)
{
    if ((ULONG)Verdict >= SB_VERDICT_NAME_COUNT) {
        return L"Unknown";
    }

    return g_VerdictNames[Verdict];
}

PCWSTR
ShadowStrikeGetAccessTypeName(
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType
)
{
    if ((ULONG)AccessType >= SB_ACCESS_TYPE_NAME_COUNT) {
        return L"Unknown";
    }

    return g_AccessTypeNames[AccessType];
}

// ============================================================================
// PRIVATE IMPLEMENTATION - CIRCUIT BREAKER
// ============================================================================

static VOID
SbpInitializeCircuitBreaker(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
)
{
    RtlZeroMemory(CircuitBreaker, sizeof(SB_CIRCUIT_BREAKER));
    CircuitBreaker->State = SbCircuitClosed;
    ExInitializePushLock(&CircuitBreaker->Lock);
    KeQuerySystemTime(&CircuitBreaker->LastStateTransition);
    CircuitBreaker->TimeoutWindowStart = CircuitBreaker->LastStateTransition;
}

static BOOLEAN
SbpCheckCircuitBreaker(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
)
{
    SB_CIRCUIT_STATE state;
    LARGE_INTEGER currentTime;
    LONG64 timeSinceOpen;

    state = (SB_CIRCUIT_STATE)CircuitBreaker->State;

    if (state == SbCircuitClosed) {
        return TRUE;
    }

    if (state == SbCircuitOpen) {
        //
        // Check if recovery time has elapsed
        //
        KeQuerySystemTime(&currentTime);
        timeSinceOpen = (currentTime.QuadPart - CircuitBreaker->OpenedTime.QuadPart) / 10000;

        if (timeSinceOpen >= SB_CIRCUIT_BREAKER_RECOVERY_MS) {
            //
            // Transition to half-open to test.
            // Use CAS to ensure only one thread wins the Openâ†’HalfOpen
            // transition; losers see the updated state and still proceed.
            //
            LONG prev = InterlockedCompareExchange(
                &CircuitBreaker->State, SbCircuitHalfOpen, SbCircuitOpen);
            if (prev == SbCircuitOpen) {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                CircuitBreaker->LastStateTransition = now;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                           "[ShadowStrike/SB] Circuit breaker: Open -> HalfOpen\n");
            }
            return TRUE;
        }

        return FALSE;
    }

    //
    // Half-open - allow one request to test
    //
    return TRUE;
}

static VOID
SbpRecordSuccess(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
)
{
    SB_CIRCUIT_STATE state = (SB_CIRCUIT_STATE)CircuitBreaker->State;

    InterlockedIncrement(&CircuitBreaker->ConsecutiveSuccesses);
    InterlockedExchange(&CircuitBreaker->ConsecutiveFailures, 0);

    if (state == SbCircuitHalfOpen) {
        //
        // Success in half-open - close the circuit
        //
        SbpTransitionCircuitState(CircuitBreaker, SbCircuitClosed);
        InterlockedExchange(&CircuitBreaker->RecentTimeouts, 0);
        InterlockedIncrement64(&CircuitBreaker->TotalRecoveries);
        BeEngineSubmitEvent(
            BehaviorEvent_CircuitBreakerRecovered,
            BehaviorCategory_Collection,
            HandleToULong(PsGetCurrentProcessId()),
            NULL,
            0,
            0,
            FALSE,
            NULL
        );
    }
}

static VOID
SbpRecordFailure(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
)
{
    SB_CIRCUIT_STATE state = (SB_CIRCUIT_STATE)CircuitBreaker->State;
    LONG failures;

    failures = InterlockedIncrement(&CircuitBreaker->ConsecutiveFailures);
    InterlockedExchange(&CircuitBreaker->ConsecutiveSuccesses, 0);
    KeQuerySystemTime(&CircuitBreaker->LastFailureTime);

    if (state == SbCircuitHalfOpen) {
        //
        // Failure in half-open - re-open the circuit
        //
        SbpTransitionCircuitState(CircuitBreaker, SbCircuitOpen);
        BeEngineSubmitEvent(
            BehaviorEvent_CircuitBreakerTripped,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL,
            0,
            30,
            FALSE,
            NULL
        );

    } else if (state == SbCircuitClosed && failures >= SB_CIRCUIT_BREAKER_THRESHOLD) {
        //
        // Too many failures - open the circuit
        //
        SbpTransitionCircuitState(CircuitBreaker, SbCircuitOpen);
        InterlockedIncrement64(&CircuitBreaker->TotalTrips);
        InterlockedIncrement(&g_ScanBridge.Stats.CircuitBreakerTrips);
        BeEngineSubmitEvent(
            BehaviorEvent_CircuitBreakerTripped,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL,
            0,
            50,
            FALSE,
            NULL
        );
    }
}

//
// Latency/health-aware trip for the *connected-but-slow* scanner.
//
// SbpRecordFailure opens the breaker only after SB_CIRCUIT_BREAKER_THRESHOLD
// CONSECUTIVE failures, and SbpRecordSuccess resets that counter on every
// success. When the user-mode scanner is connected but saturated it answers
// some create-path scans slowly (recorded as success) and lets others time out,
// so the consecutive counter never reaches the threshold — yet every
// IRP_MJ_CREATE still pays the full per-create scan timeout and aggregate file
// I/O stalls system-wide. (Field symptom: a flood of user-mode FilterReplyMessage
// NO_WAITER_FOR_REPLY with the machine frozen but no bugcheck.)
//
// This records the timeout with the existing consecutive logic AND trips on the
// timeout RATE — SB_CIRCUIT_TIMEOUT_TRIP_COUNT reply-timeouts within
// SB_CIRCUIT_TIMEOUT_WINDOW_MS — independent of interleaved successes. Once the
// breaker is open, SbpCheckCircuitBreaker short-circuits the create path before
// FltSendMessage, so a slow scanner degrades to "not scanned, allowed" for the
// recovery window instead of freezing every file open behind it.
//
static VOID
SbpRecordTimeout(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
)
{
    LARGE_INTEGER now;
    LONG64 elapsedMs;
    LONG count;

    //
    // Preserve consecutive-failure accounting: this still trips a hard-down
    // scanner quickly and drives the half-open re-open path.
    //
    SbpRecordFailure(CircuitBreaker);

    KeQuerySystemTime(&now);
    elapsedMs = (now.QuadPart - CircuitBreaker->TimeoutWindowStart.QuadPart) / 10000;

    if (elapsedMs < 0 || elapsedMs > (LONG64)SB_CIRCUIT_TIMEOUT_WINDOW_MS) {
        //
        // Start a fresh observation window. The aligned 8-byte store is atomic
        // on the x64 target; a benign race only shifts the window boundary by a
        // single sample, which the count threshold tolerates. Runs at
        // PASSIVE_LEVEL on the scan path (no lock held, no allocation).
        //
        CircuitBreaker->TimeoutWindowStart = now;
        InterlockedExchange(&CircuitBreaker->RecentTimeouts, 1);
        return;
    }

    count = InterlockedIncrement(&CircuitBreaker->RecentTimeouts);

    if (count >= SB_CIRCUIT_TIMEOUT_TRIP_COUNT &&
        (SB_CIRCUIT_STATE)CircuitBreaker->State == SbCircuitClosed) {
        //
        // Sustained slowness — open the breaker so the create path fails open
        // (fast) for the recovery window instead of taxing every file open.
        // If SbpRecordFailure above already opened it via the consecutive path,
        // the state check makes this a no-op (no double trip).
        //
        SbpTransitionCircuitState(CircuitBreaker, SbCircuitOpen);
        InterlockedIncrement64(&CircuitBreaker->TotalTrips);
        InterlockedIncrement(&g_ScanBridge.Stats.CircuitBreakerTrips);
        InterlockedExchange(&CircuitBreaker->RecentTimeouts, 0);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/SB] Circuit breaker: Closed -> Open "
                   "(scanner slow: %ld reply-timeouts within %u ms; create-path "
                   "scans fail open until recovery)\n",
                   count, (ULONG)SB_CIRCUIT_TIMEOUT_WINDOW_MS);

        BeEngineSubmitEvent(
            BehaviorEvent_CircuitBreakerTripped,
            BehaviorCategory_DefenseEvasion,
            HandleToULong(PsGetCurrentProcessId()),
            NULL,
            0,
            50,
            FALSE,
            NULL
        );
    }
}

static VOID
SbpTransitionCircuitState(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker,
    _In_ SB_CIRCUIT_STATE NewState
)
{
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&CircuitBreaker->Lock);

    CircuitBreaker->State = NewState;
    CircuitBreaker->LastStateTransition = currentTime;

    if (NewState == SbCircuitOpen) {
        CircuitBreaker->OpenedTime = currentTime;
    }

    ExReleasePushLockExclusive(&CircuitBreaker->Lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REQUEST TRACKING
// ============================================================================

static PSB_PENDING_REQUEST
SbpAllocatePendingRequest(
    VOID
)
{
    PSB_PENDING_REQUEST request;

    if (!g_ScanBridge.LookasideInitialized) {
        request = (PSB_PENDING_REQUEST)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(SB_PENDING_REQUEST),
            SB_REQUEST_TAG
        );
    } else {
        request = (PSB_PENDING_REQUEST)ExAllocateFromNPagedLookasideList(
            &g_ScanBridge.RequestLookaside
        );
    }

    if (request != NULL) {
        RtlZeroMemory(request, sizeof(SB_PENDING_REQUEST));
        InitializeListHead(&request->ListEntry);
        InitializeListHead(&request->TimeoutEntry);
        KeInitializeEvent(&request->CompletionEvent, NotificationEvent, FALSE);
    }

    return request;
}

static VOID
SbpFreePendingRequest(
    _In_ PSB_PENDING_REQUEST Request
)
{
    if (Request == NULL) {
        return;
    }

    if (!g_ScanBridge.LookasideInitialized) {
        ShadowStrikeFreePoolWithTag(Request, SB_REQUEST_TAG);
    } else {
        ExFreeToNPagedLookasideList(&g_ScanBridge.RequestLookaside, Request);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - NOTIFICATION OUTCOME ACCOUNTING
// ============================================================================

//
// Account for the outcome of a fire-and-forget notification send.
//
// Each of the four notification senders above used to do this inline as
//
//     if (NT_SUCCESS(status)) { InterlockedIncrement64(&...Notifications); }
//
// with no else, which was wrong twice over.
//
// First, failure was counted nowhere at all, so a notification the transport
// refused left no trace. That matters more now than it did: these senders route
// through ShadowStrikeSendNotification, which DROPS a message it cannot encrypt
// rather than downgrading it, so a refusal is a real event and has to be visible.
//
// Second, and worse, STATUS_TIMEOUT IS A SUCCESS CODE. FltSendMessage documents
// it as "the Timeout interval expired before the message could be delivered ...
// This is a success code", so NT_SUCCESS(STATUS_TIMEOUT) is TRUE and an
// UNDELIVERED notification was counted as a delivered one. A counter that cannot
// tell delivered from dropped answers the one question it exists to answer
// incorrectly, so the case is now split out by name.
//
// ConnectionErrors and MessageErrors were written only by SbpSendWithRetry, which
// this change removed along with the rest of the unencrypted transport. Writing
// them here keeps both counters meaningful; leaving them alone would have
// produced two statistics that read zero forever regardless of the truth.
//
static VOID
SbpAccountNotificationResult(
    _In_ NTSTATUS Status,
    _Inout_ volatile LONG64* SuccessCounter
)
{
    if (Status == STATUS_TIMEOUT) {
        //
        // Sent but NOT delivered: no user-mode thread was waiting in
        // FilterGetMessage, so the notification is gone. Counted as a transport
        // fault and never as a delivered notification.
        //
        InterlockedIncrement64(&g_ScanBridge.Stats.MessageErrors);
        return;
    }

    if (NT_SUCCESS(Status)) {
        InterlockedIncrement64(SuccessCounter);
        return;
    }

    //
    // Split the failures by cause, because the two are read differently. No
    // client, or a client whose session key is not established yet, is a
    // start-up or reconnect window that resolves itself. Anything else is a
    // delivery fault against a connected, keyed client.
    //
    if (Status == SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED ||
        Status == STATUS_PORT_DISCONNECTED ||
        Status == STATUS_ENCRYPTION_FAILED) {
        InterlockedIncrement64(&g_ScanBridge.Stats.ConnectionErrors);
    } else {
        InterlockedIncrement64(&g_ScanBridge.Stats.MessageErrors);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - STATISTICS HELPERS
// ============================================================================

static VOID
SbpUpdateLatencyStats(
    _In_ LARGE_INTEGER StartTime
)
{
    LARGE_INTEGER endTime;
    LONG64 latencyMs;
    LONG64 currentMin;
    LONG64 currentMax;

    KeQuerySystemTime(&endTime);
    latencyMs = (endTime.QuadPart - StartTime.QuadPart) / 10000;

    if (latencyMs < 0) {
        latencyMs = 0;
    }

    //
    // Update total
    //
    InterlockedAdd64(&g_ScanBridge.Stats.TotalLatencyMs, latencyMs);

    //
    // Update min (lock-free)
    //
    do {
        currentMin = g_ScanBridge.Stats.MinLatencyMs;
        if (latencyMs >= currentMin && currentMin != MAXLONGLONG) {
            break;
        }
    } while (InterlockedCompareExchange64(
        &g_ScanBridge.Stats.MinLatencyMs,
        latencyMs,
        currentMin) != currentMin);

    //
    // Update max (lock-free)
    //
    do {
        currentMax = g_ScanBridge.Stats.MaxLatencyMs;
        if (latencyMs <= currentMax) {
            break;
        }
    } while (InterlockedCompareExchange64(
        &g_ScanBridge.Stats.MaxLatencyMs,
        latencyMs,
        currentMax) != currentMax);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - RUNDOWN PROTECTION
// ============================================================================

_Must_inspect_result_
static BOOLEAN
SbpAcquireRundownProtection(
    VOID
)
{
    if (g_ScanBridge.ShuttingDown) {
        return FALSE;
    }

    return ExAcquireRundownProtection(&g_ScanBridge.RundownProtection);
}

static VOID
SbpReleaseRundownProtection(
    VOID
)
{
    ExReleaseRundownProtection(&g_ScanBridge.RundownProtection);
}
