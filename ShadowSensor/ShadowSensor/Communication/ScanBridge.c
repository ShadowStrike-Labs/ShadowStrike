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
 * Implements CrowdStrike Falcon-class scan coordination with:
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
    LARGE_INTEGER LastFailureTime;
    LARGE_INTEGER LastStateTransition;
    LARGE_INTEGER OpenedTime;
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

static NTSTATUS
SbpSendWithRetry(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_ ULONG TimeoutMs,
    _In_ ULONG MaxRetries
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
#pragma alloc_text(PAGE, ShadowStrikeScanBridgeShutdown)
#pragma alloc_text(PAGE, ShadowStrikeBuildFileScanRequest)
#pragma alloc_text(PAGE, ShadowStrikeBuildFileScanRequestEx)
#pragma alloc_text(PAGE, ShadowStrikeSendScanRequest)
#pragma alloc_text(PAGE, ShadowStrikeSendScanRequestEx)
#pragma alloc_text(PAGE, ShadowStrikeSendProcessNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendThreadNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendImageNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendRegistryNotification)
#pragma alloc_text(PAGE, ShadowStrikeSendMessage)
#pragma alloc_text(PAGE, ShadowStrikeSendMessageEx)
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
    // Atomically check and set initialization flag to prevent races
    //
    if (InterlockedCompareExchange(&g_ScanBridge.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Zero-initialize context (except Initialized which is already set)
    //
    LONG savedInit = g_ScanBridge.Initialized;
    RtlZeroMemory(&g_ScanBridge, sizeof(SB_CONTEXT));
    g_ScanBridge.Initialized = savedInit;

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
    g_ScanBridge.Stats.MinLatencyMs = MAXLONG64;

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

    PAGED_CODE();

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
    // Cleanup lookaside lists
    //
    if (g_ScanBridge.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScanBridge.StandardBufferLookaside);
        ExDeleteNPagedLookasideList(&g_ScanBridge.LargeBufferLookaside);
        ExDeleteNPagedLookasideList(&g_ScanBridge.RequestLookaside);
        g_ScanBridge.LookasideInitialized = FALSE;
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
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_ACCESS_TYPE AccessType,
    _Outptr_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
)
{
    PAGED_CODE();

    return ShadowStrikeBuildFileScanRequestEx(
        Data,
        FltObjects,
        AccessType,
        NULL,  // Default options
        Request,
        RequestSize
    );
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeBuildFileScanRequestEx(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
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
    HANDLE processId;
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
    // Acquire rundown protection
    //
    if (!SbpAcquireRundownProtection()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Get file name information
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
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
    // Get process information
    //
    processId = PsGetCurrentProcessId();

    //
    // Get process name (best effort)
    //
    status = ShadowStrikeGetProcessImageName(processId, &processName);
    if (NT_SUCCESS(status) && processName.Buffer != NULL) {
        processNameLen = processName.Length;
        if (processNameLen > SB_MAX_PROCESS_NAME_LENGTH) {
            processNameLen = SB_MAX_PROCESS_NAME_LENGTH;
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
        // Truncate path if necessary
        //
        ULONG excess = totalSize - SHADOWSTRIKE_MAX_MESSAGE_SIZE;
        if (excess < filePathLen) {
            filePathLen -= excess;
            totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
        } else {
            //
            // Cannot fit even minimal message
            //
            status = SHADOWSTRIKE_ERROR_MESSAGE_TOO_LARGE;
            goto Cleanup;
        }
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Initialize message header
    //
    status = ShadowStrikeInitMessageHeader(
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
        ShadowStrikeFreeMessageBuffer(header);
    }

    SbpReleaseRundownProtection();

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeSendScanRequest(
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
    options.MaxRetries = SB_MAX_RETRY_COUNT;

    //
    // Send with extended options
    //
    status = ShadowStrikeSendScanRequestEx(Request, RequestSize, &options, &result);

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
ShadowStrikeSendScanRequestEx(
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
        maxRetries = Options->MaxRetries > 0 ? Options->MaxRetries : SB_MAX_RETRY_COUNT;
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
    // Send request with retry
    //
    replySize = sizeof(reply);
    RtlZeroMemory(&reply, sizeof(reply));

    status = SbpSendWithRetry(
        Request,
        RequestSize,
        &reply,
        &replySize,
        timeoutMs,
        maxRetries
    );

    //
    // Record end time and calculate latency
    //
    KeQuerySystemTime(&endTime);
    Result->LatencyMs = (ULONG)((endTime.QuadPart - startTime.QuadPart) / 10000);

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
        // Record failure with circuit breaker
        //
        SbpRecordFailure(&g_ScanBridge.CircuitBreaker);
        InterlockedIncrement64(&g_ScanBridge.Stats.TimeoutScans);
        InterlockedIncrement64(&g_ScanBridge.Stats.FailedScans);

    } else {
        //
        // Other error
        //
        Result->Status = status;
        Result->Verdict = Verdict_Error;

        //
        // Record failure with circuit breaker
        //
        SbpRecordFailure(&g_ScanBridge.CircuitBreaker);
        InterlockedIncrement64(&g_ScanBridge.Stats.FailedScans);
    }

    SbpReleaseRundownProtection();

    return status;
}

// ============================================================================
// NOTIFICATION OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendProcessNotification(
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
    // Calculate total message size with overflow protection
    //
    status = SbpSafeAddUlong(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, imageNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, cmdLineLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate message buffer from lookaside list
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    status = ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageProcessNotify,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreeMessageBuffer(header);
        return status;
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
            notification->CommandLineLength = 0;
        }
    }

    //
    // Send fire-and-forget notification (no reply expected)
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_ScanBridge.Stats.ProcessNotifications);
    }

    //
    // Free message buffer back to lookaside list
    //
    ShadowStrikeFreeMessageBuffer(header);

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
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    status = ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageThreadNotify,
        sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION)
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreeMessageBuffer(header);
        return status;
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
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_ScanBridge.Stats.ThreadNotifications);
    }

    ShadowStrikeFreeMessageBuffer(header);

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
    // Get image name length
    //
    if (FullImageName != NULL && FullImageName->Buffer != NULL) {
        imageNameLen = FullImageName->Length;
    }

    //
    // Calculate size with overflow protection
    //
    status = SbpSafeAddUlong(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), sizeof(SHADOWSTRIKE_IMAGE_NOTIFICATION), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, imageNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    status = ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageImageLoad,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreeMessageBuffer(header);
        return status;
    }

    //
    // Fill notification payload
    //
    notification = (PSHADOWSTRIKE_IMAGE_NOTIFICATION)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ImageBase = (UINT64)ImageInfo->ImageBase;
    notification->ImageSize = (UINT64)ImageInfo->ImageSize;
    notification->IsSystemImage = (BOOLEAN)ImageInfo->SystemModeImage;

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
            notification->ImageNameLength = 0;
        }
    }

    //
    // Send notification
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_ScanBridge.Stats.ImageNotifications);
    }

    ShadowStrikeFreeMessageBuffer(header);

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
        return status;
    }

    status = SbpSafeAddUlong(totalSize, keyPathLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, valueNameLen, &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, sizeof(WCHAR), &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SbpSafeAddUlong(totalSize, safeDataSize, &totalSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        totalSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    status = ShadowStrikeInitMessageHeader(
        header,
        ShadowStrikeMessageRegistryNotify,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreeMessageBuffer(header);
        return status;
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
            // Failed to copy data, zero it out
            RtlZeroMemory(stringPtr, safeDataSize);
            notification->DataSize = 0;
        }
    }

    //
    // Send notification
    //
    status = ShadowStrikeSendMessage(
        header,
        totalSize,
        NULL,
        NULL,
        NULL
    );

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_ScanBridge.Stats.RegistryNotifications);
    }

    ShadowStrikeFreeMessageBuffer(header);

    return status;
}

// ============================================================================
// GENERIC MESSAGE OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendMessage(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_opt_ PLARGE_INTEGER Timeout
)
{
    ULONG timeoutMs;

    PAGED_CODE();

    //
    // Convert timeout to milliseconds
    //
    if (Timeout == NULL) {
        timeoutMs = SB_DEFAULT_SCAN_TIMEOUT_MS;
    } else if (Timeout->QuadPart == 0) {
        timeoutMs = 0;  // No wait
    } else {
        // Timeout is negative relative time in 100ns units
        timeoutMs = (ULONG)((-Timeout->QuadPart) / 10000);
    }

    return ShadowStrikeSendMessageEx(
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBufferSize,
        SbPriorityNormal,
        SB_MAX_RETRY_COUNT,
        timeoutMs
    );
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSendMessageEx(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_ SB_MESSAGE_PRIORITY Priority,
    _In_ ULONG MaxRetries,
    _In_ ULONG TimeoutMs
)
{
    NTSTATUS status;
    PFLT_PORT clientPort;

    PAGED_CODE();

    //
    // Priority is reserved for future priority-based queue routing.
    //
    UNREFERENCED_PARAMETER(Priority);

    //
    // Validate parameters
    //
    if (InputBuffer == NULL || InputBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputBufferSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        return SHADOWSTRIKE_ERROR_MESSAGE_TOO_LARGE;
    }

    //
    // Check connection
    //
    if (!ShadowStrikeIsUserModeConnected()) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Get scanner port
    //
    clientPort = ShadowStrikeGetPrimaryScannerPort();
    if (clientPort == NULL) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Send with retry logic
    //
    status = SbpSendWithRetry(
        InputBuffer,
        InputBufferSize,
        OutputBuffer,
        OutputBufferSize,
        TimeoutMs,
        MaxRetries
    );

    return status;
}

// ============================================================================
// BUFFER MANAGEMENT
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Ret_maybenull_
PVOID
ShadowStrikeAllocateMessageBuffer(
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
ShadowStrikeFreeMessageBuffer(
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
ShadowStrikeInitMessageHeader(
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

    return ShadowStrikeIsUserModeConnected();
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
    InterlockedExchange64(&g_ScanBridge.Stats.MinLatencyMs, MAXLONG64);
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
}

static BOOLEAN
SbpCheckCircuitBreaker(
    _Inout_ PSB_CIRCUIT_BREAKER CircuitBreaker
)
{
    SB_CIRCUIT_STATE state;
    LARGE_INTEGER currentTime;
    LONG64 timeSinceOpen;

    state = (SB_CIRCUIT_STATE)InterlockedCompareExchange(
        &CircuitBreaker->State,
        CircuitBreaker->State,
        CircuitBreaker->State
    );

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
            // Transition to half-open to test
            //
            SbpTransitionCircuitState(CircuitBreaker, SbCircuitHalfOpen);
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
        InterlockedIncrement64(&CircuitBreaker->TotalRecoveries);
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

    } else if (state == SbCircuitClosed && failures >= SB_CIRCUIT_BREAKER_THRESHOLD) {
        //
        // Too many failures - open the circuit
        //
        SbpTransitionCircuitState(CircuitBreaker, SbCircuitOpen);
        InterlockedIncrement64(&CircuitBreaker->TotalTrips);
        InterlockedIncrement(&g_ScanBridge.Stats.CircuitBreakerTrips);
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
// PRIVATE IMPLEMENTATION - SEND WITH RETRY
// ============================================================================

static NTSTATUS
SbpSendWithRetry(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _Inout_opt_ PULONG OutputBufferSize,
    _In_ ULONG TimeoutMs,
    _In_ ULONG MaxRetries
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    ULONG attempt;
    ULONG delayMs = SB_RETRY_DELAY_BASE_MS;
    LARGE_INTEGER delayInterval;

    //
    // Get scanner port
    //
    clientPort = ShadowStrikeGetPrimaryScannerPort();
    if (clientPort == NULL) {
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Set up timeout
    //
    if (TimeoutMs > 0) {
        timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);
    } else {
        timeout.QuadPart = 0;
    }

    //
    // Retry loop
    //
    for (attempt = 0; attempt <= MaxRetries; attempt++) {
        //
        // Send message via filter manager
        //
        status = FltSendMessage(
            g_DriverData.FilterHandle,
            &clientPort,
            InputBuffer,
            InputBufferSize,
            OutputBuffer,
            OutputBufferSize,
            TimeoutMs > 0 ? &timeout : NULL
        );

        if (NT_SUCCESS(status)) {
            return status;
        }

        //
        // Check if we should retry
        //
        if (status == STATUS_TIMEOUT ||
            status == STATUS_PORT_DISCONNECTED ||
            status == STATUS_DEVICE_NOT_READY) {

            if (attempt < MaxRetries) {
                //
                // Exponential backoff delay
                //
                InterlockedIncrement64(&g_ScanBridge.Stats.RetryCount);

                delayInterval.QuadPart = -((LONGLONG)delayMs * 10000);
                KeDelayExecutionThread(KernelMode, FALSE, &delayInterval);

                //
                // Double delay for next attempt (capped at SB_MAX_RETRY_DELAY_MS)
                //
                delayMs = delayMs * 2;
                if (delayMs > SB_MAX_RETRY_DELAY_MS) {
                    delayMs = SB_MAX_RETRY_DELAY_MS;
                }

                //
                // Refresh port in case of reconnection
                //
                clientPort = ShadowStrikeGetPrimaryScannerPort();
                if (clientPort == NULL) {
                    InterlockedIncrement64(&g_ScanBridge.Stats.ConnectionErrors);
                    return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
                }

                continue;
            }
        }

        //
        // Non-retriable error or max retries reached
        //
        break;
    }

    InterlockedIncrement64(&g_ScanBridge.Stats.MessageErrors);

    return status;
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
        if (latencyMs >= currentMin && currentMin != MAXLONG64) {
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
