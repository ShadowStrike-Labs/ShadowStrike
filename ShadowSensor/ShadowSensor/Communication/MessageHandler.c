/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE HANDLER IMPLEMENTATION
 * ============================================================================
 *
 * @file MessageHandler.c
 * @brief Enterprise-grade message dispatching and routing logic.
 *
 * This module handles all incoming messages from user-mode and routes them
 * to the appropriate subsystem handlers. It provides:
 *
 * - Message validation (magic, version, size bounds) with SEH protection
 * - User-mode buffer probing (ProbeForRead/ProbeForWrite)
 * - Authorization checks for privileged operations
 * - Safe callback invocation (copy pointer, release lock, then call)
 * - Subsystem registration and callback dispatch
 * - Configuration updates with validation
 * - Policy management
 * - Protected process registration
 * - Statistics and status queries
 * - Scan verdict processing
 *
 * Thread Safety:
 * - Handler registration protected by EX_PUSH_LOCK
 * - Configuration updates protected by driver config lock
 * - Statistics use interlocked operations
 * - Callbacks invoked outside of locks to prevent deadlock
 * - Active invocation counting for safe unregistration
 *
 * IRQL:
 * - Message processing: PASSIVE_LEVEL (may touch paged memory)
 * - Handler registration: PASSIVE_LEVEL
 * - Protected process queries: APC_LEVEL max (uses push locks)
 *
 * Security:
 * - All user-mode buffers probed and accessed under SEH
 * - Authorization required for privileged operations
 * - Input validation on all parameters
 * - ProcessName fields always null-terminated
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MessageHandler.h"
#include "MessageQueue.h"
#include "../../Shared/MessageTypes.h"
#include "../../Shared/MessageProtocol.h"
#include "../../Shared/ErrorCodes.h"
#include "../Core/Globals.h"

// ============================================================================
// CONSTANTS
// ============================================================================

#define MH_TAG                          'hMsS'
#define MH_KERNEL_BUFFER_TAG            'bMsS'

//
// Maximum size we will copy from user-mode to kernel buffer
// Prevents excessive kernel memory consumption from malicious input
//
#define MH_MAX_INPUT_BUFFER_SIZE        (64 * 1024)

// ============================================================================
// COMPILE-TIME VALIDATIONS
// ============================================================================

C_ASSERT(MH_MAX_HANDLERS >= FilterMessageType_Max);
C_ASSERT(MH_MAX_PROTECTED_PROCESSES > 0);
C_ASSERT(MH_MAX_PROTECTED_PROCESSES <= 1024);

// ============================================================================
// TYPES
// ============================================================================

/**
 * @brief Registered message handler entry.
 *
 * Contains callback pointer, context, statistics, and active invocation count.
 * The ActiveInvocations field is used for safe unregistration.
 */
typedef struct _MH_HANDLER_ENTRY {
    BOOLEAN Registered;
    UINT8 Reserved1[3];
    SHADOWSTRIKE_MESSAGE_TYPE MessageType;
    PMH_MESSAGE_HANDLER_CALLBACK Callback;
    PVOID Context;
    volatile LONG64 InvocationCount;
    volatile LONG64 ErrorCount;
    volatile LONG ActiveInvocations;  // For safe unregistration
} MH_HANDLER_ENTRY, *PMH_HANDLER_ENTRY;

/**
 * @brief Protected process entry.
 */
typedef struct _MH_PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    UINT32 ProcessId;
    UINT32 ProtectionFlags;
    LARGE_INTEGER RegistrationTime;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
} MH_PROTECTED_PROCESS, *PMH_PROTECTED_PROCESS;

C_ASSERT(sizeof(MH_PROTECTED_PROCESS) <= 1024);

/**
 * @brief Message handler global state.
 */
typedef struct _MH_GLOBALS {
    //
    // Initialization state - use interlocked operations
    //
    volatile LONG InitState;  // 0=uninit, 1=initializing, 2=initialized
    UINT8 Reserved[4];

    //
    // Handler table
    //
    MH_HANDLER_ENTRY Handlers[MH_MAX_HANDLERS];
    EX_PUSH_LOCK HandlersLock;

    //
    // Protected processes
    //
    LIST_ENTRY ProtectedProcessList;
    EX_PUSH_LOCK ProtectedProcessLock;
    volatile LONG ProtectedProcessCount;
    NPAGED_LOOKASIDE_LIST ProtectedProcessLookaside;
    BOOLEAN LookasideInitialized;
    UINT8 Reserved2[7];

    //
    // Statistics
    //
    volatile LONG64 TotalMessagesProcessed;
    volatile LONG64 TotalMessagesSucceeded;
    volatile LONG64 TotalMessagesFailed;
    volatile LONG64 TotalInvalidMessages;
    volatile LONG64 TotalUnhandledMessages;
    volatile LONG64 TotalUnauthorizedAttempts;
} MH_GLOBALS, *PMH_GLOBALS;

//
// Initialization states
//
#define MH_STATE_UNINITIALIZED      0
#define MH_STATE_INITIALIZING       1
#define MH_STATE_INITIALIZED        2

// ============================================================================
// GLOBALS
// ============================================================================

static MH_GLOBALS g_MhGlobals = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
MhpValidateAndCopyMessage(
    _In_reads_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PVOID* KernelBuffer,
    _Out_ PULONG KernelBufferSize,
    _Out_ PSS_MESSAGE_HEADER* Header,
    _Out_ PVOID* Payload,
    _Out_ PULONG PayloadSize
    );

static VOID
MhpFreeKernelBuffer(
    _In_ PVOID KernelBuffer
    );

static NTSTATUS
MhpCopyOutputToUser(
    _Out_writes_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

static BOOLEAN
MhpIsPrivilegedOperation(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    );

static NTSTATUS
MhpHandleHeartbeat(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleConfigUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandlePolicyUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleDriverStatusQuery(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleProtectedProcessRegister(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleScanVerdict(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleEnableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

static NTSTATUS
MhpHandleDisableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, MhInitialize)
#pragma alloc_text(PAGE, MhShutdown)
#pragma alloc_text(PAGE, MhRegisterHandler)
#pragma alloc_text(PAGE, MhUnregisterHandler)
#pragma alloc_text(PAGE, ShadowStrikeProcessUserMessage)
#pragma alloc_text(PAGE, MhIsCallerAuthorized)
#pragma alloc_text(PAGE, MhpValidateAndCopyMessage)
#pragma alloc_text(PAGE, MhpCopyOutputToUser)
#pragma alloc_text(PAGE, MhpHandleHeartbeat)
#pragma alloc_text(PAGE, MhpHandleConfigUpdate)
#pragma alloc_text(PAGE, MhpHandlePolicyUpdate)
#pragma alloc_text(PAGE, MhpHandleDriverStatusQuery)
#pragma alloc_text(PAGE, MhpHandleProtectedProcessRegister)
#pragma alloc_text(PAGE, MhpHandleScanVerdict)
#pragma alloc_text(PAGE, MhpHandleEnableFiltering)
#pragma alloc_text(PAGE, MhpHandleDisableFiltering)
#endif

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the message handler subsystem.
 *
 * Uses interlocked operations to prevent race conditions during initialization.
 *
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhInitialize(
    VOID
    )
{
    NTSTATUS status;
    LONG prevState;

    PAGED_CODE();

    //
    // Atomically transition from UNINITIALIZED to INITIALIZING
    // This prevents double-initialization race conditions
    //
    prevState = InterlockedCompareExchange(
        &g_MhGlobals.InitState,
        MH_STATE_INITIALIZING,
        MH_STATE_UNINITIALIZED
    );

    if (prevState == MH_STATE_INITIALIZED) {
        return STATUS_ALREADY_REGISTERED;
    }

    if (prevState == MH_STATE_INITIALIZING) {
        //
        // Another thread is initializing - this is a logic error
        //
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // We won the race - initialize everything
    // Note: Do NOT zero the structure here as InitState is already set
    //

    //
    // Initialize handler table
    //
    RtlZeroMemory(g_MhGlobals.Handlers, sizeof(g_MhGlobals.Handlers));
    ExInitializePushLock(&g_MhGlobals.HandlersLock);

    //
    // Initialize protected process list
    //
    InitializeListHead(&g_MhGlobals.ProtectedProcessList);
    ExInitializePushLock(&g_MhGlobals.ProtectedProcessLock);
    g_MhGlobals.ProtectedProcessCount = 0;

    ExInitializeNPagedLookasideList(
        &g_MhGlobals.ProtectedProcessLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MH_PROTECTED_PROCESS),
        MH_TAG,
        0
    );
    g_MhGlobals.LookasideInitialized = TRUE;

    //
    // Initialize statistics
    //
    g_MhGlobals.TotalMessagesProcessed = 0;
    g_MhGlobals.TotalMessagesSucceeded = 0;
    g_MhGlobals.TotalMessagesFailed = 0;
    g_MhGlobals.TotalInvalidMessages = 0;
    g_MhGlobals.TotalUnhandledMessages = 0;
    g_MhGlobals.TotalUnauthorizedAttempts = 0;

    //
    // Register built-in handlers - check each return value
    //
    status = MhRegisterHandler(FilterMessageType_Heartbeat, MhpHandleHeartbeat, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_ConfigUpdate, MhpHandleConfigUpdate, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_UpdatePolicy, MhpHandlePolicyUpdate, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_QueryDriverStatus, MhpHandleDriverStatusQuery, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_RegisterProtectedProcess, MhpHandleProtectedProcessRegister, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_ScanVerdict, MhpHandleScanVerdict, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_EnableFiltering, MhpHandleEnableFiltering, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    status = MhRegisterHandler(FilterMessageType_DisableFiltering, MhpHandleDisableFiltering, NULL);
    if (!NT_SUCCESS(status)) {
        goto CleanupOnError;
    }

    //
    // Mark as fully initialized
    //
    InterlockedExchange(&g_MhGlobals.InitState, MH_STATE_INITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Message handler initialized\n");

    return STATUS_SUCCESS;

CleanupOnError:
    //
    // Cleanup on initialization failure
    //
    if (g_MhGlobals.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside);
        g_MhGlobals.LookasideInitialized = FALSE;
    }

    InterlockedExchange(&g_MhGlobals.InitState, MH_STATE_UNINITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[ShadowStrike/MH] Initialization failed: 0x%08X\n", status);

    return status;
}

/**
 * @brief Shutdown the message handler subsystem.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MhShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    LONG state;

    PAGED_CODE();

    state = InterlockedCompareExchange(
        &g_MhGlobals.InitState,
        MH_STATE_UNINITIALIZED,
        MH_STATE_INITIALIZED
    );

    if (state != MH_STATE_INITIALIZED) {
        return;
    }

    //
    // Clear protected process list under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    while (!IsListEmpty(&g_MhGlobals.ProtectedProcessList)) {
        entry = RemoveHeadList(&g_MhGlobals.ProtectedProcessList);
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        ExFreeToNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside, protectedProcess);
    }
    g_MhGlobals.ProtectedProcessCount = 0;

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (g_MhGlobals.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside);
        g_MhGlobals.LookasideInitialized = FALSE;
    }

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Shutdown - Processed=%lld, Succeeded=%lld, Failed=%lld, Invalid=%lld, Unauthorized=%lld\n",
               g_MhGlobals.TotalMessagesProcessed,
               g_MhGlobals.TotalMessagesSucceeded,
               g_MhGlobals.TotalMessagesFailed,
               g_MhGlobals.TotalInvalidMessages,
               g_MhGlobals.TotalUnauthorizedAttempts);
}

// ============================================================================
// HANDLER REGISTRATION
// ============================================================================

/**
 * @brief Register a message handler callback.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhRegisterHandler(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ PMH_MESSAGE_HANDLER_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    ULONG slot;

    PAGED_CODE();

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((ULONG)MessageType >= MH_MAX_HANDLERS) {
        return STATUS_INVALID_PARAMETER;
    }

    slot = (ULONG)MessageType;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);

    if (g_MhGlobals.Handlers[slot].Registered) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();
        return STATUS_ALREADY_REGISTERED;
    }

    g_MhGlobals.Handlers[slot].MessageType = MessageType;
    g_MhGlobals.Handlers[slot].Callback = Callback;
    g_MhGlobals.Handlers[slot].Context = Context;
    g_MhGlobals.Handlers[slot].InvocationCount = 0;
    g_MhGlobals.Handlers[slot].ErrorCount = 0;
    g_MhGlobals.Handlers[slot].ActiveInvocations = 0;

    //
    // Memory barrier before setting Registered to ensure all fields are visible
    //
    MemoryBarrier();
    g_MhGlobals.Handlers[slot].Registered = TRUE;

    ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister a message handler.
 *
 * Waits for active invocations to complete before returning.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MhUnregisterHandler(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    )
{
    ULONG slot;
    LONG activeCount;
    ULONG waitCount = 0;
    const ULONG maxWaitIterations = 1000;  // 10 seconds max

    PAGED_CODE();

    if ((ULONG)MessageType >= MH_MAX_HANDLERS) {
        return STATUS_INVALID_PARAMETER;
    }

    slot = (ULONG)MessageType;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);

    if (!g_MhGlobals.Handlers[slot].Registered) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Mark as unregistered first - new callers will see this
    //
    g_MhGlobals.Handlers[slot].Registered = FALSE;
    MemoryBarrier();

    //
    // Wait for active invocations to complete
    //
    while ((activeCount = g_MhGlobals.Handlers[slot].ActiveInvocations) > 0) {
        ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
        KeLeaveCriticalRegion();

        if (++waitCount > maxWaitIterations) {
            //
            // Timeout waiting for callbacks - log and continue
            // This should not happen in normal operation
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] Timeout waiting for handler %u to drain (active=%d)\n",
                       MessageType, activeCount);
            break;
        }

        //
        // Wait 10ms and retry
        //
        LARGE_INTEGER delay;
        delay.QuadPart = -100000;  // 10ms in 100ns units
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_MhGlobals.HandlersLock);
    }

    //
    // Clear the handler entry
    //
    g_MhGlobals.Handlers[slot].Callback = NULL;
    g_MhGlobals.Handlers[slot].Context = NULL;

    ExReleasePushLockExclusive(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// AUTHORIZATION
// ============================================================================

/**
 * @brief Check if the calling process is authorized for privileged operations.
 *
 * Authorization is granted if:
 * 1. Caller is running as LocalSystem, OR
 * 2. Caller is a registered protected ShadowStrike process
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
MhIsCallerAuthorized(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext
    )
{
    SECURITY_SUBJECT_CONTEXT subjectContext;
    PACCESS_TOKEN token;
    BOOLEAN isSystem = FALSE;
    PTOKEN_USER tokenUser = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (ClientContext == NULL) {
        return FALSE;
    }

    //
    // Check if this is the primary scanner connection (implicitly trusted)
    //
    if (ClientContext->IsPrimaryScanner) {
        return TRUE;
    }

    //
    // Check if caller's PID is in protected process list
    //
    if (ClientContext->ClientProcessId != NULL) {
        UINT32 pid = (UINT32)(ULONG_PTR)ClientContext->ClientProcessId;
        if (MhIsProcessProtected(pid)) {
            return TRUE;
        }
    }

    //
    // Check if caller is running as SYSTEM
    //
    SeCaptureSubjectContext(&subjectContext);
    token = SeQuerySubjectContextToken(&subjectContext);

    if (token != NULL) {
        status = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
        if (NT_SUCCESS(status) && tokenUser != NULL) {
            //
            // Check for LocalSystem SID (S-1-5-18)
            //
            SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
            UCHAR systemSidBuffer[SECURITY_MAX_SID_SIZE];
            PSID systemSid = (PSID)systemSidBuffer;

            status = RtlInitializeSid(systemSid, &ntAuthority, 1);
            if (NT_SUCCESS(status)) {
                *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
                isSystem = RtlEqualSid(tokenUser->User.Sid, systemSid);
            }

            ExFreePool(tokenUser);
        }
    }

    SeReleaseSubjectContext(&subjectContext);

    return isSystem;
}

/**
 * @brief Check if a message type requires authorization.
 */
static BOOLEAN
MhpIsPrivilegedOperation(
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType
    )
{
    switch (MessageType) {
        case FilterMessageType_EnableFiltering:
        case FilterMessageType_DisableFiltering:
        case FilterMessageType_UpdatePolicy:
        case FilterMessageType_ConfigUpdate:
        case FilterMessageType_RegisterProtectedProcess:
            return TRUE;
        default:
            return FALSE;
    }
}

// ============================================================================
// USER-MODE BUFFER HANDLING
// ============================================================================

/**
 * @brief Validate user buffer, probe it, and copy to kernel memory.
 *
 * This function:
 * 1. Probes the user buffer for read access
 * 2. Allocates a kernel buffer
 * 3. Copies the data under SEH protection
 * 4. Validates the message header
 *
 * On success, caller must free KernelBuffer with MhpFreeKernelBuffer().
 */
static NTSTATUS
MhpValidateAndCopyMessage(
    _In_reads_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PVOID* KernelBuffer,
    _Out_ PULONG KernelBufferSize,
    _Out_ PSS_MESSAGE_HEADER* Header,
    _Out_ PVOID* Payload,
    _Out_ PULONG PayloadSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID kernelBuf = NULL;
    PSS_MESSAGE_HEADER hdr;

    PAGED_CODE();

    *KernelBuffer = NULL;
    *KernelBufferSize = 0;
    *Header = NULL;
    *Payload = NULL;
    *PayloadSize = 0;

    //
    // Basic parameter validation
    //
    if (UserBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (UserBufferSize < sizeof(SS_MESSAGE_HEADER)) {
        return SHADOWSTRIKE_ERROR_BUFFER_TOO_SMALL;
    }

    if (UserBufferSize > MH_MAX_INPUT_BUFFER_SIZE) {
        return SHADOWSTRIKE_ERROR_BUFFER_TOO_SMALL;
    }

    //
    // Allocate kernel buffer
    //
    kernelBuf = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED,
        UserBufferSize,
        MH_KERNEL_BUFFER_TAG
    );

    if (kernelBuf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Probe and copy under SEH
    //
    __try {
        //
        // Probe for read access - this validates the user pointer
        //
        ProbeForRead(UserBuffer, UserBufferSize, sizeof(UCHAR));

        //
        // Copy to kernel buffer
        //
        RtlCopyMemory(kernelBuf, UserBuffer, UserBufferSize);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return status;
    }

    //
    // Now validate the copied header (safe kernel memory)
    //
    hdr = (PSS_MESSAGE_HEADER)kernelBuf;

    //
    // Validate magic
    //
    if (hdr->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Validate version
    //
    if (hdr->Version != SHADOWSTRIKE_PROTOCOL_VERSION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Version mismatch: got %u, expected %u\n",
                   hdr->Version, SHADOWSTRIKE_PROTOCOL_VERSION);
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_VERSION_MISMATCH;
    }

    //
    // Validate sizes - prevent integer overflow
    //
    if (hdr->TotalSize > UserBufferSize) {
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Safe subtraction - we already validated UserBufferSize >= sizeof(SS_MESSAGE_HEADER)
    //
    ULONG maxPayloadSize = UserBufferSize - sizeof(SS_MESSAGE_HEADER);
    if (hdr->DataSize > maxPayloadSize) {
        ExFreePoolWithTag(kernelBuf, MH_KERNEL_BUFFER_TAG);
        return SHADOWSTRIKE_ERROR_INVALID_MESSAGE;
    }

    //
    // Success - return kernel buffer and parsed pointers
    //
    *KernelBuffer = kernelBuf;
    *KernelBufferSize = UserBufferSize;
    *Header = hdr;

    if (hdr->DataSize > 0) {
        *Payload = (PUCHAR)kernelBuf + sizeof(SS_MESSAGE_HEADER);
        *PayloadSize = hdr->DataSize;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Free kernel buffer allocated by MhpValidateAndCopyMessage.
 */
static VOID
MhpFreeKernelBuffer(
    _In_ PVOID KernelBuffer
    )
{
    if (KernelBuffer != NULL) {
        ExFreePoolWithTag(KernelBuffer, MH_KERNEL_BUFFER_TAG);
    }
}

/**
 * @brief Copy output data to user buffer with SEH protection.
 */
static NTSTATUS
MhpCopyOutputToUser(
    _Out_writes_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (UserBuffer == NULL || Data == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize > UserBufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    __try {
        ProbeForWrite(UserBuffer, DataSize, sizeof(UCHAR));
        RtlCopyMemory(UserBuffer, Data, DataSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

// ============================================================================
// MAIN MESSAGE PROCESSING
// ============================================================================

/**
 * @brief Process a message from user-mode.
 *
 * This is the main entry point for handling messages. It:
 * 1. Validates parameters
 * 2. Copies input buffer to kernel memory with probing
 * 3. Validates message header
 * 4. Checks authorization for privileged operations
 * 5. Looks up and invokes the handler (outside the lock)
 * 6. Copies output back to user with probing
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeProcessUserMessage(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_reads_bytes_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status;
    PVOID kernelBuffer = NULL;
    ULONG kernelBufferSize = 0;
    PSS_MESSAGE_HEADER header = NULL;
    PVOID payload = NULL;
    ULONG payloadSize = 0;
    PMH_HANDLER_ENTRY handlerEntry = NULL;
    PMH_MESSAGE_HANDLER_CALLBACK callback = NULL;
    PVOID context = NULL;
    ULONG slot;
    UCHAR localOutputBuffer[256];
    ULONG localOutputLength = 0;

    PAGED_CODE();

    //
    // Validate required parameters
    //
    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ClientContext == NULL) {
        *ReturnOutputBufferLength = 0;
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize output
    //
    *ReturnOutputBufferLength = 0;

    //
    // Check if initialized
    //
    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return SHADOWSTRIKE_ERROR_NOT_INITIALIZED;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MhGlobals.TotalMessagesProcessed);

    //
    // Validate and copy input buffer to kernel memory
    //
    status = MhpValidateAndCopyMessage(
        InputBuffer,
        InputBufferSize,
        &kernelBuffer,
        &kernelBufferSize,
        &header,
        &payload,
        &payloadSize
    );

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_MhGlobals.TotalInvalidMessages);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid message received: 0x%08X\n", status);
        return status;
    }

    //
    // Check authorization for privileged operations
    //
    if (MhpIsPrivilegedOperation((SHADOWSTRIKE_MESSAGE_TYPE)header->MessageType)) {
        if (!MhIsCallerAuthorized(ClientContext)) {
            InterlockedIncrement64(&g_MhGlobals.TotalUnauthorizedAttempts);
            MhpFreeKernelBuffer(kernelBuffer);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/MH] Unauthorized attempt for message type %u from PID %p\n",
                       header->MessageType, ClientContext->ClientProcessId);

            return STATUS_ACCESS_DENIED;
        }
    }

    //
    // Look up handler
    //
    slot = (ULONG)header->MessageType;
    if (slot >= MH_MAX_HANDLERS) {
        InterlockedIncrement64(&g_MhGlobals.TotalUnhandledMessages);
        MhpFreeKernelBuffer(kernelBuffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Message type out of range: %u\n", header->MessageType);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get handler under shared lock, copy callback/context, then release lock
    // This prevents deadlock if callback tries to register/unregister handlers
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.HandlersLock);

    handlerEntry = &g_MhGlobals.Handlers[slot];
    if (handlerEntry->Registered && handlerEntry->Callback != NULL) {
        callback = handlerEntry->Callback;
        context = handlerEntry->Context;
        InterlockedIncrement(&handlerEntry->ActiveInvocations);
        InterlockedIncrement64(&handlerEntry->InvocationCount);
    }

    ExReleasePushLockShared(&g_MhGlobals.HandlersLock);
    KeLeaveCriticalRegion();

    //
    // If no handler, not an error - just no handler registered
    //
    if (callback == NULL) {
        InterlockedIncrement64(&g_MhGlobals.TotalUnhandledMessages);
        MhpFreeKernelBuffer(kernelBuffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike/MH] No handler for message type: %u\n", header->MessageType);
        return STATUS_SUCCESS;
    }

    //
    // Call handler with kernel-mode buffers (safe)
    // Use local output buffer first, then copy to user
    //
    RtlZeroMemory(localOutputBuffer, sizeof(localOutputBuffer));

    status = callback(
        ClientContext,
        header,
        payload,
        payloadSize,
        (OutputBuffer != NULL) ? localOutputBuffer : NULL,
        (OutputBuffer != NULL) ? min(OutputBufferSize, sizeof(localOutputBuffer)) : 0,
        &localOutputLength
    );

    //
    // Decrement active invocations
    //
    InterlockedDecrement(&handlerEntry->ActiveInvocations);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&handlerEntry->ErrorCount);
    }

    //
    // Free kernel input buffer
    //
    MhpFreeKernelBuffer(kernelBuffer);
    kernelBuffer = NULL;

    //
    // Copy output to user buffer if needed
    //
    if (NT_SUCCESS(status) && OutputBuffer != NULL && localOutputLength > 0) {
        if (localOutputLength <= OutputBufferSize) {
            NTSTATUS copyStatus = MhpCopyOutputToUser(
                OutputBuffer,
                OutputBufferSize,
                localOutputBuffer,
                localOutputLength
            );

            if (NT_SUCCESS(copyStatus)) {
                *ReturnOutputBufferLength = localOutputLength;
            } else {
                //
                // Failed to copy output - don't fail the whole operation
                // as the handler already succeeded
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/MH] Failed to copy output to user: 0x%08X\n", copyStatus);
            }
        }
    }

    //
    // Update statistics
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_MhGlobals.TotalMessagesSucceeded);
    } else {
        InterlockedIncrement64(&g_MhGlobals.TotalMessagesFailed);
    }

    return status;
}

// ============================================================================
// BUILT-IN HANDLERS
// ============================================================================

/**
 * @brief Handle heartbeat message.
 */
static NTSTATUS
MhpHandleHeartbeat(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Send simple acknowledgment reply if buffer provided
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;  // Success
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle configuration update message.
 *
 * This handler exists for backward compatibility but returns NOT_IMPLEMENTED
 * to indicate clients should use PolicyUpdate instead.
 */
static NTSTATUS
MhpHandleConfigUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] ConfigUpdate is deprecated - use PolicyUpdate instead\n");

    //
    // Return NOT_IMPLEMENTED to signal clients should migrate to PolicyUpdate
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)STATUS_NOT_IMPLEMENTED;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Handle policy update message.
 */
static NTSTATUS
MhpHandlePolicyUpdate(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_POLICY_UPDATE policy;
    PSHADOWSTRIKE_GENERIC_REPLY reply;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload size
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_POLICY_UPDATE)) {
        return STATUS_INVALID_PARAMETER;
    }

    policy = (PSHADOWSTRIKE_POLICY_UPDATE)PayloadBuffer;

    //
    // Validate policy values
    //
    if (policy->ScanTimeoutMs < SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS ||
        policy->ScanTimeoutMs > SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid scan timeout: %u (range: %u-%u)\n",
                   policy->ScanTimeoutMs,
                   SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS,
                   SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate MaxPendingRequests
    //
    if (policy->MaxPendingRequests == 0 || policy->MaxPendingRequests > 100000) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Invalid MaxPendingRequests: %u\n",
                   policy->MaxPendingRequests);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Apply policy to driver configuration under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.ScanOnOpen = policy->ScanOnOpen;
    g_DriverData.Config.ScanOnExecute = policy->ScanOnExecute;
    g_DriverData.Config.ScanOnWrite = policy->ScanOnWrite;
    g_DriverData.Config.NotificationsEnabled = policy->EnableNotifications;
    g_DriverData.Config.BlockOnTimeout = policy->BlockOnTimeout;
    g_DriverData.Config.BlockOnError = policy->BlockOnError;
    g_DriverData.Config.ScanNetworkFiles = policy->ScanNetworkFiles;
    g_DriverData.Config.ScanRemovableMedia = policy->ScanRemovableMedia;
    g_DriverData.Config.MaxScanFileSize = policy->MaxScanFileSize;
    g_DriverData.Config.ScanTimeoutMs = policy->ScanTimeoutMs;
    g_DriverData.Config.CacheTTLSeconds = policy->CacheTTLSeconds;
    g_DriverData.Config.MaxPendingRequests = policy->MaxPendingRequests;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Policy updated: ScanOnOpen=%d, ScanOnExec=%d, Timeout=%u\n",
               policy->ScanOnOpen, policy->ScanOnExecute, policy->ScanTimeoutMs);

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)status;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return status;
}

/**
 * @brief Handle driver status query.
 */
static NTSTATUS
MhpHandleDriverStatusQuery(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    SHADOWSTRIKE_DRIVER_STATUS driverStatus;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Validate output buffer
    //
    if (OutputBuffer == NULL || OutputBufferSize < sizeof(SHADOWSTRIKE_DRIVER_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&driverStatus, sizeof(driverStatus));

    //
    // Fill driver status
    //
    driverStatus.VersionMajor = SHADOWSTRIKE_VERSION_MAJOR;
    driverStatus.VersionMinor = SHADOWSTRIKE_VERSION_MINOR;
    driverStatus.VersionBuild = SHADOWSTRIKE_VERSION_BUILD;

    //
    // Read config under shared lock for consistency
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ConfigLock);

    driverStatus.FilteringActive = g_DriverData.Config.FilteringEnabled && g_DriverData.FilteringStarted;
    driverStatus.ScanOnOpenEnabled = g_DriverData.Config.ScanOnOpen;
    driverStatus.ScanOnExecuteEnabled = g_DriverData.Config.ScanOnExecute;
    driverStatus.ScanOnWriteEnabled = g_DriverData.Config.ScanOnWrite;
    driverStatus.NotificationsEnabled = g_DriverData.Config.NotificationsEnabled;

    ExReleasePushLockShared(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    //
    // Read statistics (volatile, no lock needed for approximate values)
    //
    driverStatus.TotalFilesScanned = (UINT64)g_DriverData.Stats.TotalFilesScanned;
    driverStatus.FilesBlocked = (UINT64)g_DriverData.Stats.FilesBlocked;
    driverStatus.CacheHits = (UINT64)g_DriverData.Stats.CacheHits;
    driverStatus.CacheMisses = (UINT64)g_DriverData.Stats.CacheMisses;
    driverStatus.PendingRequests = g_DriverData.Stats.PendingRequests;
    driverStatus.PeakPendingRequests = g_DriverData.Stats.PeakPendingRequests;
    driverStatus.ConnectedClients = g_DriverData.ConnectedClients;

    //
    // Copy to output buffer (already validated as kernel memory by caller)
    //
    RtlCopyMemory(OutputBuffer, &driverStatus, sizeof(driverStatus));
    *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_DRIVER_STATUS);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle protected process registration.
 */
static NTSTATUS
MhpHandleProtectedProcessRegister(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_PROTECTED_PROCESS request;
    PSHADOWSTRIKE_GENERIC_REPLY reply;
    PMH_PROTECTED_PROCESS newEntry = NULL;
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS existingEntry;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN found = FALSE;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_PROTECTED_PROCESS)) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (PSHADOWSTRIKE_PROTECTED_PROCESS)PayloadBuffer;

    //
    // Validate process ID
    //
    if (request->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire exclusive lock for the entire operation to prevent race
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    //
    // Check limit INSIDE the lock to prevent race condition
    //
    if (g_MhGlobals.ProtectedProcessCount >= MH_MAX_PROTECTED_PROCESSES) {
        ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Max protected processes reached (%d)\n",
                   MH_MAX_PROTECTED_PROCESSES);
        return SHADOWSTRIKE_ERROR_MAX_PROTECTED;
    }

    //
    // Check if already registered
    //
    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        existingEntry = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (existingEntry->ProcessId == request->ProcessId) {
            //
            // Update existing entry
            //
            existingEntry->ProtectionFlags = request->ProtectionFlags;

            //
            // Copy ProcessName with guaranteed null-termination
            //
            RtlCopyMemory(
                existingEntry->ProcessName,
                request->ProcessName,
                sizeof(existingEntry->ProcessName) - sizeof(WCHAR)
            );
            existingEntry->ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = L'\0';

            found = TRUE;
            break;
        }
    }

    if (!found) {
        //
        // Allocate new entry from lookaside list
        //
        newEntry = (PMH_PROTECTED_PROCESS)ExAllocateFromNPagedLookasideList(
            &g_MhGlobals.ProtectedProcessLookaside);

        if (newEntry == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            RtlZeroMemory(newEntry, sizeof(MH_PROTECTED_PROCESS));
            newEntry->ProcessId = request->ProcessId;
            newEntry->ProtectionFlags = request->ProtectionFlags;
            KeQuerySystemTime(&newEntry->RegistrationTime);

            //
            // Copy ProcessName with guaranteed null-termination
            //
            RtlCopyMemory(
                newEntry->ProcessName,
                request->ProcessName,
                sizeof(newEntry->ProcessName) - sizeof(WCHAR)
            );
            newEntry->ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = L'\0';

            InsertTailList(&g_MhGlobals.ProtectedProcessList, &newEntry->ListEntry);
            InterlockedIncrement(&g_MhGlobals.ProtectedProcessCount);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MH] Protected process registered: PID=%u, Flags=0x%08X\n",
                       request->ProcessId, request->ProtectionFlags);
        }
    }

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = (UINT32)status;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return status;
}

/**
 * @brief Handle scan verdict message (response to a scan request).
 */
static NTSTATUS
MhpHandleScanVerdict(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_SCAN_VERDICT_REPLY verdict;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;

    //
    // Validate payload
    //
    if (PayloadBuffer == NULL || PayloadSize < sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)) {
        return STATUS_INVALID_PARAMETER;
    }

    verdict = (PSHADOWSTRIKE_SCAN_VERDICT_REPLY)PayloadBuffer;

    //
    // Route to MessageQueue completion mechanism
    // This completes the blocking message waiting for this verdict
    //
    status = MqCompleteMessage(
        verdict->MessageId,
        STATUS_SUCCESS,
        verdict,
        PayloadSize
    );

    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/MH] Failed to complete scan verdict: id=%llu, status=0x%08X\n",
                   verdict->MessageId, status);
    }

    //
    // Update statistics
    //
    SHADOWSTRIKE_INC_STAT(RepliesReceived);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle enable filtering command.
 */
static NTSTATUS
MhpHandleEnableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Enable filtering under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = TRUE;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Filtering enabled\n");

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Handle disable filtering command.
 */
static NTSTATUS
MhpHandleDisableFiltering(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PSS_MESSAGE_HEADER Header,
    _In_reads_bytes_opt_(PayloadSize) PVOID PayloadBuffer,
    _In_ ULONG PayloadSize,
    _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ClientContext);
    UNREFERENCED_PARAMETER(PayloadBuffer);
    UNREFERENCED_PARAMETER(PayloadSize);

    *ReturnOutputBufferLength = 0;

    //
    // Disable filtering under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = FALSE;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/MH] Filtering disabled\n");

    //
    // Send reply
    //
    if (OutputBuffer != NULL && OutputBufferSize >= sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        reply = (PSHADOWSTRIKE_GENERIC_REPLY)OutputBuffer;
        reply->MessageId = Header->MessageId;
        reply->Status = 0;
        reply->Reserved = 0;
        *ReturnOutputBufferLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PROTECTED PROCESS QUERIES
// ============================================================================

/**
 * @brief Check if a process is protected.
 *
 * Safe to call from IRQL <= APC_LEVEL.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MhIsProcessProtected(
    _In_ UINT32 ProcessId
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    BOOLEAN found = FALSE;

    if (ProcessId == 0) {
        return FALSE;
    }

    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return found;
}

/**
 * @brief Get protection flags for a process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MhGetProcessProtectionFlags(
    _In_ UINT32 ProcessId,
    _Out_ PUINT32 Flags
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = 0;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return SHADOWSTRIKE_ERROR_NOT_INITIALIZED;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            *Flags = protectedProcess->ProtectionFlags;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockShared(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return status;
}

/**
 * @brief Remove a protected process (e.g., on process termination).
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MhUnprotectProcess(
    _In_ UINT32 ProcessId
    )
{
    PLIST_ENTRY entry;
    PMH_PROTECTED_PROCESS protectedProcess;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_MhGlobals.InitState != MH_STATE_INITIALIZED) {
        return SHADOWSTRIKE_ERROR_NOT_INITIALIZED;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);

    for (entry = g_MhGlobals.ProtectedProcessList.Flink;
         entry != &g_MhGlobals.ProtectedProcessList;
         entry = entry->Flink)
    {
        protectedProcess = CONTAINING_RECORD(entry, MH_PROTECTED_PROCESS, ListEntry);
        if (protectedProcess->ProcessId == ProcessId) {
            RemoveEntryList(&protectedProcess->ListEntry);
            ExFreeToNPagedLookasideList(&g_MhGlobals.ProtectedProcessLookaside, protectedProcess);
            InterlockedDecrement(&g_MhGlobals.ProtectedProcessCount);
            status = STATUS_SUCCESS;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/MH] Protected process removed: PID=%u\n", ProcessId);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_MhGlobals.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return status;
}
