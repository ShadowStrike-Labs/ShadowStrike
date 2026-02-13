/**
 * ============================================================================
 * ShadowStrike NGAV - KTM TRANSACTION MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file KtmMonitor.c
 * @brief Enterprise-grade ransomware detection via Kernel Transaction Manager.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "KtmMonitor.h"

// ============================================================================
// GLOBAL STATE
// ============================================================================

SHADOW_KTM_MONITOR_STATE g_KtmMonitorState = { 0 };

// ============================================================================
// CONSTANTS
// ============================================================================

static const WCHAR* g_RansomwareTargetExtensions[] = {
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx",
    L".pdf", L".txt", L".jpg", L".png", L".mp4", L".avi",
    L".zip", L".rar", L".7z", L".sql", L".mdb", L".accdb",
    L".psd", L".dwg", L".dxf", L".ai", L".eps", L".indd",
    L".csv", L".dat", L".db", L".log", L".sav", L".tar",
    NULL
};

static const WCHAR* g_SuspiciousProcessNames[] = {
    L"powershell.exe",
    L"cmd.exe",
    L"wscript.exe",
    L"cscript.exe",
    L"mshta.exe",
    L"rundll32.exe",
    L"regsvr32.exe",
    L"certutil.exe",
    NULL
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static BOOLEAN
ShadowIsSuspiciousProcessCached(
    _In_ PCWSTR ProcessName
    );

static NTSTATUS
ShadowCreateKtmCommunicationPort(
    _In_ PFLT_FILTER FilterHandle
    );

#define SHADOW_KTM_PORT_NAME L"\\ShadowStrikeKtmPort"

// ============================================================================
// REFERENCE COUNTING — CAS LOOP IMPLEMENTATION
// ============================================================================

/**
 * @brief Acquire additional reference via atomic CAS loop.
 *
 * Returns FALSE if refcount is <= 0 or is the DESTROYING sentinel,
 * meaning the transaction is being freed and must not be touched.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowReferenceKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    )
{
    LONG oldRefCount;
    LONG newRefCount;

    if (Transaction == NULL) {
        return FALSE;
    }

    for (;;) {
        oldRefCount = Transaction->ReferenceCount;

        if (oldRefCount <= 0 || oldRefCount == SHADOW_KTM_REFCOUNT_DESTROYING) {
            return FALSE;
        }

        newRefCount = oldRefCount + 1;

        if (InterlockedCompareExchange(
                &Transaction->ReferenceCount,
                newRefCount,
                oldRefCount) == oldRefCount) {
            return TRUE;
        }

        //
        // CAS failed — another thread modified the refcount. Retry.
        //
    }
}

/**
 * @brief Release transaction reference.
 *
 * On final release (refcount → 0), sets DESTROYING sentinel and frees.
 * On detected underflow or double-free, logs and leaks rather than
 * crashing the customer's machine.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowReleaseKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    )
{
    LONG newRefCount;

    if (Transaction == NULL) {
        return;
    }

    //
    // Validate magic before touching refcount. If magic is wrong,
    // we are operating on freed / corrupted memory — do not touch it.
    //
    if (Transaction->Magic != SHADOW_KTM_TRANSACTION_MAGIC) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] KTM: Release called on transaction with bad magic "
                   "(0x%08lX != 0x%08lX) — memory corruption suspected, leaking\n",
                   Transaction->Magic, SHADOW_KTM_TRANSACTION_MAGIC);
        InterlockedIncrement64(&g_KtmMonitorState.Stats.RefCountRaces);
        return;
    }

    //
    // Pre-check: if refcount is already <= 0 this is a double-free.
    // Log and leak — never crash the customer's machine for a refcount bug.
    //
    if (Transaction->ReferenceCount <= 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] KTM: Double-release detected (refcount=%ld, "
                   "GUID={%08lX-...}). Leaking to prevent use-after-free.\n",
                   Transaction->ReferenceCount,
                   Transaction->TransactionGuid.Data1);
        InterlockedIncrement64(&g_KtmMonitorState.Stats.RefCountRaces);
        return;
    }

    newRefCount = InterlockedDecrement(&Transaction->ReferenceCount);

    if (newRefCount == 0) {
        //
        // Set DESTROYING sentinel so concurrent ShadowReferenceKtmTransaction
        // callers will see it and back off before we actually free.
        //
        InterlockedExchange(&Transaction->ReferenceCount, SHADOW_KTM_REFCOUNT_DESTROYING);

        //
        // Poison the magic to detect use-after-free in debug builds.
        //
        Transaction->Magic = 0xDEADBEEF;

        ExFreePoolWithTag(Transaction, SHADOW_KTM_TRANSACTION_TAG);
    }
    else if (newRefCount < 0) {
        //
        // Underflow race — restore and leak. Do NOT bugcheck.
        //
        InterlockedIncrement(&Transaction->ReferenceCount);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] KTM: Refcount underflow after decrement "
                   "(newRefCount=%ld). Leaking transaction.\n", newRefCount);
        InterlockedIncrement64(&g_KtmMonitorState.Stats.RefCountRaces);
    }
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * @brief Validate transaction structure integrity.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowValidateKtmTransaction(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    )
{
    if (Transaction == NULL) {
        return FALSE;
    }

    if (Transaction->Magic != SHADOW_KTM_TRANSACTION_MAGIC) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] KTM: Transaction magic mismatch "
                   "(0x%08lX != 0x%08lX)\n",
                   Transaction->Magic, SHADOW_KTM_TRANSACTION_MAGIC);
        return FALSE;
    }

    if (Transaction->ReferenceCount <= 0) {
        return FALSE;
    }

    if (Transaction->ThreatScore < 0 || Transaction->ThreatScore > 100) {
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// PROCESS NAME HELPER (PASSIVE_LEVEL ONLY)
// ============================================================================

/**
 * @brief Get process image name. Allocates from NonPagedPool so the
 *        returned buffer is safe to use at any IRQL for reads.
 *        Caller frees ImageName->Buffer with SHADOW_KTM_STRING_TAG.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImageName
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING processImageName = NULL;

    ImageName->Buffer = NULL;
    ImageName->Length = 0;
    ImageName->MaximumLength = 0;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(process, &processImageName);
    if (NT_SUCCESS(status) && processImageName != NULL && processImageName->Buffer != NULL) {

        ImageName->MaximumLength = processImageName->Length + sizeof(WCHAR);
        ImageName->Buffer = (PWCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            ImageName->MaximumLength,
            SHADOW_KTM_STRING_TAG
        );

        if (ImageName->Buffer != NULL) {
            RtlCopyUnicodeString(ImageName, processImageName);
            //
            // Guarantee null-termination for safe %ws usage
            //
            ImageName->Buffer[ImageName->Length / sizeof(WCHAR)] = L'\0';
        } else {
            ImageName->MaximumLength = 0;
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        ExFreePool(processImageName);
    }

    ObDereferenceObject(process);
    return status;
}

/**
 * @brief Check if cached process name matches a suspicious process.
 *        Uses only the embedded ProcessName field — safe at any IRQL.
 */
static BOOLEAN
ShadowIsSuspiciousProcessCached(
    _In_ PCWSTR ProcessName
    )
{
    ULONG i;
    UNICODE_STRING nameStr;
    UNICODE_STRING suspiciousStr;

    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return FALSE;
    }

    RtlInitUnicodeString(&nameStr, ProcessName);

    for (i = 0; g_SuspiciousProcessNames[i] != NULL; i++) {
        RtlInitUnicodeString(&suspiciousStr, g_SuspiciousProcessNames[i]);

        //
        // Case-insensitive substring search using UNICODE_STRING APIs.
        // Check if the suspicious name appears anywhere in the path.
        //
        if (nameStr.Length >= suspiciousStr.Length) {
            USHORT maxOffset = (nameStr.Length - suspiciousStr.Length) / sizeof(WCHAR);
            for (USHORT offset = 0; offset <= maxOffset; offset++) {
                UNICODE_STRING sub;
                sub.Buffer = nameStr.Buffer + offset;
                sub.Length = suspiciousStr.Length;
                sub.MaximumLength = suspiciousStr.Length;

                if (RtlEqualUnicodeString(&sub, &suspiciousStr, TRUE)) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ============================================================================
// COMMUNICATION PORT IMPLEMENTATION
// ============================================================================

NTSTATUS
ShadowKtmPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    PAGED_CODE();

    if (!state->Initialized || state->ShuttingDown) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // MaxConnections=1 in FltCreateCommunicationPort provides the primary
    // guard. This check is defense-in-depth.
    //
    if (InterlockedCompareExchangePointer(
            (PVOID*)&state->ClientPort, ClientPort, NULL) != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] KTM port: Rejecting additional connection\n");
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    *ConnectionPortCookie = state;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] KTM port: Client connected (PID=%p)\n",
               PsGetCurrentProcessId());

    return STATUS_SUCCESS;
}

VOID
ShadowKtmPortDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    PSHADOW_KTM_MONITOR_STATE state = (PSHADOW_KTM_MONITOR_STATE)ConnectionCookie;

    PAGED_CODE();

    if (state != NULL && state->ClientPort != NULL) {
        FltCloseClientPort(state->FilterHandle, &state->ClientPort);
        state->ClientPort = NULL;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] KTM port: Client disconnected\n");
    }
}

/**
 * @brief Message notify callback for KTM port.
 *
 * The OutputBuffer comes from user mode. We must probe it before writing.
 */
NTSTATUS
ShadowKtmPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PSHADOW_KTM_MONITOR_STATE state = (PSHADOW_KTM_MONITOR_STATE)PortCookie;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PAGED_CODE();

    *ReturnOutputBufferLength = 0;

    if (state == NULL || !state->Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Handle statistics query — probe the user-mode output buffer first.
    //
    if (OutputBuffer != NULL && OutputBufferLength >= sizeof(SHADOW_KTM_STATISTICS)) {
        __try {
            ProbeForWrite(OutputBuffer, sizeof(SHADOW_KTM_STATISTICS), sizeof(ULONG));
            ShadowGetKtmStatistics((PSHADOW_KTM_STATISTICS)OutputBuffer);
            *ReturnOutputBufferLength = sizeof(SHADOW_KTM_STATISTICS);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] KTM port: Exception probing output buffer: 0x%X\n",
                       GetExceptionCode());
            return GetExceptionCode();
        }
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Create KTM communication port with restricted DACL.
 */
static NTSTATUS
ShadowCreateKtmCommunicationPort(
    _In_ PFLT_FILTER FilterHandle
    )
{
    NTSTATUS status;
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;

    PAGED_CODE();

    if (FilterHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    state->FilterHandle = FilterHandle;

    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor,
        FLT_PORT_ALL_ACCESS
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to build security descriptor: 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&portName, SHADOW_KTM_PORT_NAME);

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        securityDescriptor
    );

    status = FltCreateCommunicationPort(
        FilterHandle,
        &state->ServerPort,
        &objectAttributes,
        state,
        ShadowKtmPortConnectNotify,
        ShadowKtmPortDisconnectNotify,
        ShadowKtmPortMessageNotify,
        1
    );

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to create KTM communication port: 0x%X\n", status);
        state->ServerPort = NULL;
        return status;
    }

    state->CommunicationPortOpen = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] KTM communication port created: %wZ\n", &portName);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowInitializeKtmMonitor(
    _In_ PFLT_FILTER FilterHandle
    )
{
    NTSTATUS status;
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    LONG previousState;
    LARGE_INTEGER sleepInterval;

    PAGED_CODE();

    previousState = InterlockedCompareExchange(
        &state->InitializationState,
        KTM_STATE_INITIALIZING,
        KTM_STATE_UNINITIALIZED
    );

    if (previousState == KTM_STATE_INITIALIZED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] KTM monitor already initialized\n");
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState == KTM_STATE_INITIALIZING) {
        sleepInterval.QuadPart = -((LONGLONG)50 * 10000LL);

        for (ULONG i = 0; i < 100; i++) {
            KeDelayExecutionThread(KernelMode, FALSE, &sleepInterval);

            if (state->InitializationState == KTM_STATE_INITIALIZED) {
                return STATUS_SUCCESS;
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] KTM monitor initialization timeout\n");
        return STATUS_TIMEOUT;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing KTM Transaction Monitor v3.1\n");

    //
    // Initialize synchronization
    //
    FsRtlInitializePushLock(&state->Lock);
    state->LockInitialized = TRUE;

    KeInitializeSpinLock(&state->AlertLock);
    KeInitializeSpinLock(&state->StatsLock);

    //
    // Initialize lookaside lists for high-performance allocation
    //
    ExInitializeNPagedLookasideList(
        &state->TransactionLookaside,
        NULL, NULL, 0,
        sizeof(SHADOW_KTM_TRANSACTION),
        SHADOW_KTM_TRANSACTION_TAG,
        0
    );
    state->TransactionLookasideInitialized = TRUE;

    ExInitializeNPagedLookasideList(
        &state->AlertLookaside,
        NULL, NULL, 0,
        sizeof(SHADOW_KTM_ALERT),
        SHADOW_KTM_ALERT_TAG,
        0
    );
    state->AlertLookasideInitialized = TRUE;

    //
    // Initialize transaction tracking list
    //
    InitializeListHead(&state->TransactionList);
    state->TransactionCount = 0;
    state->MaxTransactions = SHADOW_MAX_TRANSACTIONS;

    //
    // Initialize alert queue
    //
    InitializeListHead(&state->AlertQueue);
    state->AlertCount = 0;
    state->MaxAlerts = SHADOW_MAX_KTM_ALERT_QUEUE;

    //
    // Configuration defaults
    //
    state->MonitoringEnabled = TRUE;
    state->BlockingEnabled = FALSE;
    state->RansomwareDetectionEnabled = TRUE;
    state->RateLimitingEnabled = TRUE;
    state->ThreatThreshold = SHADOW_KTM_THREAT_THRESHOLD;
    state->RansomwareThreshold = SHADOW_RANSOMWARE_THRESHOLD_FILES_PER_SEC;
    state->RateLimitWindow.QuadPart = SHADOW_RANSOMWARE_DETECTION_WINDOW_MS * 10000LL;

    RtlZeroMemory(&state->Stats, sizeof(SHADOW_KTM_STATISTICS));

    //
    // Register transaction object callbacks
    //
    status = ShadowRegisterTransactionCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to register transaction callbacks: 0x%X\n", status);
        goto cleanup;
    }

    //
    // Create communication port (non-fatal if it fails)
    //
    status = ShadowCreateKtmCommunicationPort(FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] KTM comm port creation failed: 0x%X (non-fatal)\n", status);
        state->ServerPort = NULL;
        state->ClientPort = NULL;
        state->CommunicationPortOpen = FALSE;
    }

    //
    // Mark as initialized
    //
    KeQuerySystemTime(&state->InitTime);
    state->Initialized = TRUE;
    InterlockedExchange(&state->ShuttingDown, FALSE);
    InterlockedExchange(&state->InitializationState, KTM_STATE_INITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] KTM Transaction Monitor initialized successfully\n");

    return STATUS_SUCCESS;

cleanup:
    InterlockedExchange(&state->InitializationState, KTM_STATE_UNINITIALIZED);
    ShadowCleanupKtmMonitor();
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupKtmMonitor(
    VOID
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Cleaning up KTM Transaction Monitor\n");

    //
    // Signal shutdown
    //
    InterlockedExchange(&state->ShuttingDown, TRUE);
    InterlockedExchange(&state->InitializationState, KTM_STATE_SHUTTING_DOWN);

    //
    // Unregister callbacks FIRST — no new callbacks after this returns
    //
    ShadowUnregisterTransactionCallbacks();

    //
    // Now safe to drain transaction entries
    //
    ShadowCleanupTransactionEntries();
    ShadowCleanupKtmAlertQueue();

    //
    // Close communication ports — server port first to stop new connections,
    // then client port.
    //
    if (state->ServerPort != NULL) {
        FltCloseCommunicationPort(state->ServerPort);
        state->ServerPort = NULL;
    }

    if (state->ClientPort != NULL) {
        FltCloseClientPort(state->FilterHandle, &state->ClientPort);
        state->ClientPort = NULL;
    }

    state->CommunicationPortOpen = FALSE;

    //
    // Delete lookaside lists
    //
    if (state->TransactionLookasideInitialized) {
        ExDeleteNPagedLookasideList(&state->TransactionLookaside);
        state->TransactionLookasideInitialized = FALSE;
    }

    if (state->AlertLookasideInitialized) {
        ExDeleteNPagedLookasideList(&state->AlertLookaside);
        state->AlertLookasideInitialized = FALSE;
    }

    //
    // Delete push lock
    //
    if (state->LockInitialized) {
        FsRtlDeletePushLock(&state->Lock);
        state->LockInitialized = FALSE;
    }

    state->Initialized = FALSE;
    InterlockedExchange(&state->InitializationState, KTM_STATE_UNINITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] KTM Transaction Monitor cleaned up\n");
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowRegisterTransactionCallbacks(
    VOID
    )
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operationRegistration[2];
    OB_CALLBACK_REGISTRATION callbackRegistration;
    UNICODE_STRING altitude;
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    POBJECT_TYPE tmTxObjectType = NULL;
    POBJECT_TYPE tmRmObjectType = NULL;
    UNICODE_STRING tmTxTypeName;
    UNICODE_STRING tmRmTypeName;
    PVOID* pTmTxType;
    PVOID* pTmRmType;
    USHORT operationCount;

    PAGED_CODE();

    if (state->CallbacksRegistered) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlInitUnicodeString(&tmTxTypeName, L"TmTransactionObjectType");
    RtlInitUnicodeString(&tmRmTypeName, L"TmResourceManagerObjectType");

    pTmTxType = (PVOID*)MmGetSystemRoutineAddress(&tmTxTypeName);
    pTmRmType = (PVOID*)MmGetSystemRoutineAddress(&tmRmTypeName);

    if (pTmTxType != NULL && *pTmTxType != NULL) {
        tmTxObjectType = (POBJECT_TYPE)*pTmTxType;
    }

    if (pTmRmType != NULL && *pTmRmType != NULL) {
        tmRmObjectType = (POBJECT_TYPE)*pTmRmType;
    }

    if (tmTxObjectType == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] TmTx type not available — fallback mode\n");
        state->TransactionCallbackHandle = NULL;
        state->CallbacksRegistered = FALSE;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(operationRegistration, sizeof(operationRegistration));

    operationRegistration[0].ObjectType = tmTxObjectType;
    operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = ShadowTransactionPreOperationCallback;
    operationRegistration[0].PostOperation = ShadowTransactionPostOperationCallback;

    operationCount = 1;

    if (tmRmObjectType != NULL) {
        operationRegistration[1].ObjectType = tmRmObjectType;
        operationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operationRegistration[1].PreOperation = ShadowTransactionPreOperationCallback;
        operationRegistration[1].PostOperation = ShadowTransactionPostOperationCallback;
        operationCount = 2;
    }

    RtlInitUnicodeString(&altitude, L"385200");

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = operationCount;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = state;
    callbackRegistration.OperationRegistration = operationRegistration;

    status = ObRegisterCallbacks(
        &callbackRegistration,
        &state->TransactionCallbackHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ObRegisterCallbacks failed: 0x%X — fallback mode\n", status);
        state->TransactionCallbackHandle = NULL;
        state->CallbacksRegistered = FALSE;
        return STATUS_SUCCESS;
    }

    state->CallbacksRegistered = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Transaction callbacks registered (TmTx=YES, TmRm=%s)\n",
               tmRmObjectType != NULL ? "YES" : "NO");

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowUnregisterTransactionCallbacks(
    VOID
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;

    PAGED_CODE();

    if (state->CallbacksRegistered && state->TransactionCallbackHandle != NULL) {
        ObUnRegisterCallbacks(state->TransactionCallbackHandle);
        state->TransactionCallbackHandle = NULL;
        state->CallbacksRegistered = FALSE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Transaction callbacks unregistered\n");
    }
}

// ============================================================================
// TRANSACTION TRACKING
// ============================================================================

/**
 * @brief Track a new transaction.
 *
 * Allocates via lookaside list, sets magic, captures process name at
 * PASSIVE_LEVEL, inserts into LRU list.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowTrackTransaction(
    _In_ GUID TransactionGuid,
    _In_ HANDLE ProcessId,
    _Outptr_ PSHADOW_KTM_TRANSACTION* Transaction
    )
{
    PSHADOW_KTM_TRANSACTION transaction = NULL;
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    UNICODE_STRING imageN = { 0 };
    NTSTATUS status;

    PAGED_CODE();

    *Transaction = NULL;

    if (!state->Initialized || state->ShuttingDown) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Allocate from lookaside list (NonPagedPool, pre-sized)
    //
    if (state->TransactionLookasideInitialized) {
        transaction = (PSHADOW_KTM_TRANSACTION)ExAllocateFromNPagedLookasideList(
            &state->TransactionLookaside
        );
    } else {
        transaction = (PSHADOW_KTM_TRANSACTION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(SHADOW_KTM_TRANSACTION),
            SHADOW_KTM_TRANSACTION_TAG
        );
    }

    if (transaction == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(transaction, sizeof(SHADOW_KTM_TRANSACTION));

    //
    // Set magic for validation
    //
    transaction->Magic = SHADOW_KTM_TRANSACTION_MAGIC;
    RtlCopyMemory(&transaction->TransactionGuid, &TransactionGuid, sizeof(GUID));
    transaction->ProcessId = ProcessId;
    transaction->ReferenceCount = 1;
    transaction->RemovedFromList = FALSE;

    KeQuerySystemTime(&transaction->CreateTime);
    transaction->LastActivityTime = transaction->CreateTime;
    transaction->RateWindowStart = transaction->CreateTime;

    //
    // Capture process name at PASSIVE_LEVEL (safe here)
    //
    status = ShadowGetProcessImageName(ProcessId, &imageN);
    if (NT_SUCCESS(status) && imageN.Buffer != NULL) {
        USHORT copyLength = min(imageN.Length / sizeof(WCHAR), SHADOW_MAX_PROCESS_NAME - 1);
        RtlCopyMemory(
            transaction->ProcessName,
            imageN.Buffer,
            copyLength * sizeof(WCHAR)
        );
        transaction->ProcessName[copyLength] = L'\0';
        ExFreePoolWithTag(imageN.Buffer, SHADOW_KTM_STRING_TAG);
    }

    //
    // Insert into LRU list
    //
    FsRtlAcquirePushLockExclusive(&state->Lock);

    if ((ULONG)state->TransactionCount >= state->MaxTransactions) {
        ShadowEvictLruTransaction();
    }

    InsertHeadList(&state->TransactionList, &transaction->ListEntry);
    InterlockedIncrement(&state->TransactionCount);

    FsRtlReleasePushLockExclusive(&state->Lock);

    InterlockedIncrement64(&state->Stats.TotalTransactions);

    *Transaction = transaction;
    return STATUS_SUCCESS;
}

/**
 * @brief Find existing transaction by GUID.
 *
 * Uses CAS-based reference increment under exclusive lock to prevent
 * use-after-free.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowFindKtmTransaction(
    _In_ GUID TransactionGuid,
    _Outptr_ PSHADOW_KTM_TRANSACTION* Transaction
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    PLIST_ENTRY entry;
    PSHADOW_KTM_TRANSACTION transaction;
    BOOLEAN found = FALSE;

    *Transaction = NULL;

    if (!state->Initialized || state->ShuttingDown) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    FsRtlAcquirePushLockExclusive(&state->Lock);

    for (entry = state->TransactionList.Flink;
         entry != &state->TransactionList;
         entry = entry->Flink) {

        transaction = CONTAINING_RECORD(entry, SHADOW_KTM_TRANSACTION, ListEntry);

        if (RtlCompareMemory(&transaction->TransactionGuid,
                             &TransactionGuid, sizeof(GUID)) == sizeof(GUID)) {

            //
            // Use CAS loop to safely acquire reference.
            // Under exclusive lock, this is belt-and-suspenders.
            //
            if (!ShadowReferenceKtmTransaction(transaction)) {
                InterlockedIncrement64(&state->Stats.RefCountRaces);
                continue;
            }

            *Transaction = transaction;
            found = TRUE;

            //
            // Update activity time
            //
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            InterlockedExchange64(
                &transaction->LastActivityTime.QuadPart,
                currentTime.QuadPart);

            //
            // Move to front (LRU)
            //
            RemoveEntryList(&transaction->ListEntry);
            InsertHeadList(&state->TransactionList, &transaction->ListEntry);

            InterlockedIncrement64(&state->Stats.CacheHits);
            break;
        }
    }

    FsRtlReleasePushLockExclusive(&state->Lock);

    if (!found) {
        InterlockedIncrement64(&state->Stats.CacheMisses);
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// THREAT SCORING (DISPATCH_LEVEL SAFE — uses cached data only)
// ============================================================================

/**
 * @brief Calculate threat score using cached process name (no IRQL issues).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowCalculateKtmThreatScore(
    _In_ PSHADOW_KTM_TRANSACTION Transaction,
    _In_ SHADOW_KTM_OPERATION Operation,
    _Out_ PULONG ThreatScore
    )
{
    ULONG score = 0;
    LARGE_INTEGER currentTime;
    LONGLONG timeDelta;
    ULONG filesPerSecond;

    UNREFERENCED_PARAMETER(Operation);

    *ThreatScore = 0;

    if (!ShadowValidateKtmTransaction(Transaction)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // FACTOR 1: High-velocity file operations
    //
    if (Transaction->FilesModified > 10) {
        KeQuerySystemTime(&currentTime);
        timeDelta = currentTime.QuadPart - Transaction->RateWindowStart.QuadPart;

        if (timeDelta > 0) {
            LONGLONG filesModified64 = (LONGLONG)Transaction->FilesModified;
            LONGLONG numerator = filesModified64 * 10000000LL;

            if (numerator / 10000000LL != filesModified64) {
                filesPerSecond = ULONG_MAX;
            } else {
                filesPerSecond = (ULONG)(numerator / timeDelta);
            }

            if (filesPerSecond >= g_KtmMonitorState.RansomwareThreshold) {
                score += 60;
                Transaction->HasRansomwarePattern = TRUE;
            }
            else if (filesPerSecond >= (g_KtmMonitorState.RansomwareThreshold / 2)) {
                score += 30;
            }
        }
    }

    //
    // FACTOR 2: Suspicious process (uses cached name — safe at any IRQL)
    //
    if (ShadowIsSuspiciousProcessCached(Transaction->ProcessName)) {
        score += 15;
    }

    //
    // FACTOR 3: Large operation counts
    //
    if (Transaction->FileOperationCount > 100) {
        score += 10;
    }

    if (Transaction->RegistryOperationCount > 50) {
        score += 10;
    }

    //
    // FACTOR 4: Commit after mass operations
    //
    if (Transaction->IsCommitted && Transaction->FilesModified > 20) {
        score += 15;
    }

    if (score > 100) {
        score = 100;
    }

    *ThreatScore = score;
    InterlockedExchange(&Transaction->ThreatScore, (LONG)score);

    return STATUS_SUCCESS;
}

// ============================================================================
// FILE EXTENSION CHECK (DISPATCH_LEVEL SAFE — pool-allocated buffer)
// ============================================================================

/**
 * @brief Check if file extension is a ransomware target.
 *
 * Allocates a temporary buffer from NonPagedPool instead of using a
 * large stack buffer. Uses RtlDowncaseUnicodeChar for kernel-safe
 * lowercasing.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowIsRansomwareTargetFile(
    _In_ PUNICODE_STRING FilePath
    )
{
    ULONG i;
    PWCHAR extension;
    PWCHAR lowerBuf;
    USHORT charCount;
    USHORT idx;
    UNICODE_STRING extStr;
    UNICODE_STRING targetStr;
    BOOLEAN result = FALSE;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    charCount = FilePath->Length / sizeof(WCHAR);
    if (charCount == 0 || charCount > SHADOW_MAX_FILE_PATH) {
        return FALSE;
    }

    //
    // Allocate from NonPagedPool — safe at DISPATCH_LEVEL
    //
    lowerBuf = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)(charCount + 1) * sizeof(WCHAR),
        SHADOW_KTM_STRING_TAG
    );

    if (lowerBuf == NULL) {
        return FALSE;
    }

    //
    // Copy and lowercase using kernel-safe RtlDowncaseUnicodeChar
    //
    for (idx = 0; idx < charCount; idx++) {
        lowerBuf[idx] = RtlDowncaseUnicodeChar(FilePath->Buffer[idx]);
    }
    lowerBuf[charCount] = L'\0';

    //
    // Find last dot
    //
    extension = NULL;
    for (idx = charCount; idx > 0; idx--) {
        if (lowerBuf[idx - 1] == L'.') {
            extension = &lowerBuf[idx - 1];
            break;
        }
        if (lowerBuf[idx - 1] == L'\\' || lowerBuf[idx - 1] == L'/') {
            break;
        }
    }

    if (extension != NULL) {
        RtlInitUnicodeString(&extStr, extension);

        for (i = 0; g_RansomwareTargetExtensions[i] != NULL; i++) {
            RtlInitUnicodeString(&targetStr, g_RansomwareTargetExtensions[i]);
            if (RtlEqualUnicodeString(&extStr, &targetStr, FALSE)) {
                result = TRUE;
                break;
            }
        }
    }

    ExFreePoolWithTag(lowerBuf, SHADOW_KTM_STRING_TAG);
    return result;
}

/**
 * @brief Detect ransomware file modification pattern.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowDetectRansomwarePattern(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    )
{
    LARGE_INTEGER currentTime;
    LONGLONG timeDelta;
    ULONG filesPerSecond;
    LONGLONG filesModified64;
    LONGLONG numerator;

    if (Transaction == NULL) {
        return FALSE;
    }

    if (Transaction->HasRansomwarePattern) {
        return TRUE;
    }

    if (Transaction->FilesModified < 10) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);
    timeDelta = currentTime.QuadPart - Transaction->RateWindowStart.QuadPart;

    if (timeDelta <= 0) {
        return FALSE;
    }

    filesModified64 = (LONGLONG)Transaction->FilesModified;
    numerator = filesModified64 * 10000000LL;

    if (numerator / 10000000LL != filesModified64) {
        filesPerSecond = ULONG_MAX;
    } else {
        filesPerSecond = (ULONG)(numerator / timeDelta);
    }

    if (filesPerSecond >= g_KtmMonitorState.RansomwareThreshold) {
        Transaction->HasRansomwarePattern = TRUE;
        InterlockedIncrement64(&g_KtmMonitorState.Stats.RansomwareDetections);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] RANSOMWARE DETECTED! PID=%p (%ws), Files/Sec=%lu\n",
                   Transaction->ProcessId, Transaction->ProcessName, filesPerSecond);

        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// FILE OPERATION RECORDING
// ============================================================================

/**
 * @brief Record transacted file operation.
 *
 * Must be called at PASSIVE_LEVEL because ShadowQueueKtmAlert captures
 * process name via ShadowGetProcessImageName (PsLookupProcessByProcessId).
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowRecordTransactedFileOperation(
    _In_ PSHADOW_KTM_TRANSACTION Transaction,
    _In_ PUNICODE_STRING FilePath
    )
{
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (Transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement(&Transaction->FileOperationCount);
    InterlockedIncrement64(&g_KtmMonitorState.Stats.TransactedFileOperations);

    if (FilePath != NULL && ShadowIsRansomwareTargetFile(FilePath)) {
        InterlockedIncrement(&Transaction->FilesModified);
        InterlockedIncrement64(&g_KtmMonitorState.Stats.FilesEncrypted);
    }

    KeQuerySystemTime(&currentTime);
    InterlockedExchange64(&Transaction->LastActivityTime.QuadPart, currentTime.QuadPart);

    if (ShadowDetectRansomwarePattern(Transaction)) {
        ULONG threatScore = 0;
        ShadowCalculateKtmThreatScore(Transaction, KtmOperationFileWrite, &threatScore);

        ShadowQueueKtmAlert(
            KtmAlertRansomware,
            Transaction->ProcessId,
            Transaction->ProcessName,
            Transaction->TransactionGuid,
            (ULONG)Transaction->FilesModified,
            threatScore,
            Transaction->IsBlocked
        );
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Mark transaction as committed.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowMarkTransactionCommitted(
    _In_ PSHADOW_KTM_TRANSACTION Transaction
    )
{
    ULONG threatScore = 0;

    PAGED_CODE();

    if (Transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Transaction->IsCommitted = TRUE;
    KeQuerySystemTime(&Transaction->CommitTime);

    InterlockedIncrement64(&g_KtmMonitorState.Stats.TotalCommits);

    if (Transaction->FilesModified > 20) {
        InterlockedIncrement64(&g_KtmMonitorState.Stats.MassCommitOperations);

        ShadowCalculateKtmThreatScore(Transaction, KtmOperationCommit, &threatScore);

        if (threatScore >= g_KtmMonitorState.ThreatThreshold) {
            ShadowQueueKtmAlert(
                KtmAlertMassCommit,
                Transaction->ProcessId,
                Transaction->ProcessName,
                Transaction->TransactionGuid,
                (ULONG)Transaction->FilesModified,
                threatScore,
                Transaction->IsBlocked
            );
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get atomic snapshot of statistics under spinlock.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowGetKtmStatistics(
    _Out_ PSHADOW_KTM_STATISTICS Stats
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    KIRQL oldIrql;

    if (Stats == NULL) {
        return;
    }

    KeAcquireSpinLock(&state->StatsLock, &oldIrql);
    RtlCopyMemory(Stats, &state->Stats, sizeof(SHADOW_KTM_STATISTICS));
    KeReleaseSpinLock(&state->StatsLock, oldIrql);
}

// ============================================================================
// ALERT QUEUE
// ============================================================================

/**
 * @brief Queue a KTM threat alert. ProcessName is used from the caller's
 *        pre-captured buffer (safe at any IRQL). If NULL, we leave it blank.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowQueueKtmAlert(
    _In_ SHADOW_KTM_ALERT_TYPE AlertType,
    _In_ HANDLE ProcessId,
    _In_opt_ PCWSTR ProcessName,
    _In_ GUID TransactionGuid,
    _In_ ULONG FilesAffected,
    _In_ ULONG ThreatScore,
    _In_ BOOLEAN WasBlocked
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    PSHADOW_KTM_ALERT alert = NULL;
    KIRQL oldIrql;

    //
    // Allocate from lookaside (NonPagedPool — safe at DISPATCH)
    //
    if (state->AlertLookasideInitialized) {
        alert = (PSHADOW_KTM_ALERT)ExAllocateFromNPagedLookasideList(
            &state->AlertLookaside
        );
    } else {
        alert = (PSHADOW_KTM_ALERT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(SHADOW_KTM_ALERT),
            SHADOW_KTM_ALERT_TAG
        );
    }

    if (alert == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(alert, sizeof(SHADOW_KTM_ALERT));

    alert->AlertType = AlertType;
    alert->ThreatScore = ThreatScore;
    alert->ProcessId = ProcessId;
    RtlCopyMemory(&alert->TransactionGuid, &TransactionGuid, sizeof(GUID));
    alert->FilesAffected = FilesAffected;
    alert->WasBlocked = WasBlocked;
    KeQuerySystemTime(&alert->AlertTime);

    //
    // Copy pre-captured process name (safe at any IRQL)
    //
    if (ProcessName != NULL) {
        NTSTATUS copyStatus = RtlStringCchCopyW(
            alert->ProcessName,
            SHADOW_MAX_PROCESS_NAME,
            ProcessName
        );
        if (!NT_SUCCESS(copyStatus)) {
            alert->ProcessName[0] = L'\0';
        }
    }

    //
    // Insert into queue under spinlock. Alert count is modified only
    // under this spinlock, so use plain increment (not Interlocked).
    //
    KeAcquireSpinLock(&state->AlertLock, &oldIrql);

    if (state->AlertCount >= (LONG)state->MaxAlerts) {
        PLIST_ENTRY oldEntry = RemoveTailList(&state->AlertQueue);
        PSHADOW_KTM_ALERT oldAlert = CONTAINING_RECORD(oldEntry, SHADOW_KTM_ALERT, ListEntry);
        state->AlertCount--;

        if (state->AlertLookasideInitialized) {
            ExFreeToNPagedLookasideList(&state->AlertLookaside, oldAlert);
        } else {
            ExFreePoolWithTag(oldAlert, SHADOW_KTM_ALERT_TAG);
        }
    }

    InsertHeadList(&state->AlertQueue, &alert->ListEntry);
    state->AlertCount++;

    KeReleaseSpinLock(&state->AlertLock, oldIrql);

    InterlockedIncrement64(&state->Stats.ThreatAlerts);

    return STATUS_SUCCESS;
}

// ============================================================================
// MINIFILTER TRANSACTION NOTIFICATION
// ============================================================================

/**
 * @brief Minifilter transaction notification callback.
 *
 * Handles commit/rollback notifications from Filter Manager for transactions
 * the minifilter has enlisted in.
 */
NTSTATUS
ShadowKtmNotificationCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG NotificationMask
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(TransactionContext);

    if (NotificationMask & TRANSACTION_NOTIFY_COMMIT) {
        InterlockedIncrement64(&g_KtmMonitorState.Stats.TotalCommits);
    }

    if (NotificationMask & TRANSACTION_NOTIFY_ROLLBACK) {
        InterlockedIncrement64(&g_KtmMonitorState.Stats.TotalRollbacks);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// OB CALLBACK FUNCTIONS
// ============================================================================

/**
 * @brief Pre-operation callback for transaction object access.
 *
 * Called at PASSIVE_LEVEL by the Object Manager. Exception handling is
 * scoped narrowly around the ObQueryNameString path (which can fail
 * with STATUS_ACCESS_VIOLATION on certain object types).
 */
OB_PREOP_CALLBACK_STATUS
ShadowTransactionPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PSHADOW_KTM_MONITOR_STATE state = (PSHADOW_KTM_MONITOR_STATE)RegistrationContext;
    ACCESS_MASK requestedAccess;
    NTSTATUS status;
    GUID transactionGuid = { 0 };
    PSHADOW_KTM_TRANSACTION transaction = NULL;
    ULONG threatScore = 0;
    HANDLE currentProcessId;
    POBJECT_NAME_INFORMATION objectNameInfo = NULL;
    ULONG returnLength = 0;

    if (OperationInformation == NULL || OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (state == NULL || !state->Initialized || state->ShuttingDown || !state->MonitoringEnabled) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        requestedAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        requestedAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if ((requestedAccess & SUSPICIOUS_TRANSACTION_ACCESS) == 0) {
        return OB_PREOP_SUCCESS;
    }

    InterlockedIncrement64(&state->Stats.SuspiciousTransactions);
    currentProcessId = PsGetCurrentProcessId();

    //
    // Narrow exception scope: ObQueryNameString can fail on certain
    // object types with access violations. We handle only those.
    //
    __try {
        status = ObQueryNameString(
            OperationInformation->Object,
            NULL, 0, &returnLength
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Exception in ObQueryNameString (size query): 0x%X\n",
                   GetExceptionCode());
        return OB_PREOP_SUCCESS;
    }

    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Cap allocation to prevent abuse via inflated returnLength
    //
    if (returnLength > 4096) {
        return OB_PREOP_SUCCESS;
    }

    objectNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        returnLength,
        SHADOW_KTM_STRING_TAG
    );

    if (objectNameInfo == NULL) {
        return OB_PREOP_SUCCESS;
    }

    __try {
        status = ObQueryNameString(
            OperationInformation->Object,
            objectNameInfo,
            returnLength,
            &returnLength
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(objectNameInfo, SHADOW_KTM_STRING_TAG);
        return OB_PREOP_SUCCESS;
    }

    if (!NT_SUCCESS(status) || objectNameInfo->Name.Buffer == NULL) {
        ExFreePoolWithTag(objectNameInfo, SHADOW_KTM_STRING_TAG);
        return OB_PREOP_SUCCESS;
    }

    //
    // Ensure the name buffer is null-terminated for safe RtlInitUnicodeString usage
    //
    if (objectNameInfo->Name.Length < objectNameInfo->Name.MaximumLength) {
        objectNameInfo->Name.Buffer[objectNameInfo->Name.Length / sizeof(WCHAR)] = L'\0';
    }

    //
    // Find GUID in the object name
    //
    PWCHAR guidStart = NULL;
    USHORT nameChars = objectNameInfo->Name.Length / sizeof(WCHAR);
    for (USHORT idx = 0; idx < nameChars; idx++) {
        if (objectNameInfo->Name.Buffer[idx] == L'{') {
            guidStart = &objectNameInfo->Name.Buffer[idx];
            break;
        }
    }

    if (guidStart != NULL) {
        UNICODE_STRING guidString;
        RtlInitUnicodeString(&guidString, guidStart);

        status = RtlGUIDFromString(&guidString, &transactionGuid);
        if (NT_SUCCESS(status)) {

            status = ShadowFindKtmTransaction(transactionGuid, &transaction);

            if (status == STATUS_NOT_FOUND) {
                status = ShadowTrackTransaction(
                    transactionGuid,
                    currentProcessId,
                    &transaction
                );
            }

            if (NT_SUCCESS(status) && transaction != NULL) {

                ShadowCalculateKtmThreatScore(
                    transaction,
                    KtmOperationCreate,
                    &threatScore
                );

                if (state->BlockingEnabled &&
                    threatScore >= state->ThreatThreshold) {

                    transaction->IsBlocked = TRUE;
                    InterlockedIncrement64(&state->Stats.BlockedTransactions);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike] BLOCKED: PID=%p, Score=%lu, "
                               "GUID={%08lX-...}\n",
                               currentProcessId, threatScore,
                               transactionGuid.Data1);

                    ShadowQueueKtmAlert(
                        KtmAlertRansomware,
                        currentProcessId,
                        transaction->ProcessName,
                        transactionGuid,
                        (ULONG)transaction->FilesModified,
                        threatScore,
                        TRUE
                    );

                    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                            ~(TRANSACTION_COMMIT | TRANSACTION_ROLLBACK);
                    } else {
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
                            ~(TRANSACTION_COMMIT | TRANSACTION_ROLLBACK);
                    }
                }

                ShadowReleaseKtmTransaction(transaction);
            }
        }
    }

    ExFreePoolWithTag(objectNameInfo, SHADOW_KTM_STRING_TAG);

    return OB_PREOP_SUCCESS;
}

/**
 * @brief Post-operation callback for transaction access.
 *
 * Records telemetry for completed handle operations.
 */
VOID
ShadowTransactionPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
    )
{
    PSHADOW_KTM_MONITOR_STATE state = (PSHADOW_KTM_MONITOR_STATE)RegistrationContext;

    if (state == NULL || !state->Initialized || state->ShuttingDown) {
        return;
    }

    if (OperationInformation == NULL) {
        return;
    }

    //
    // Record the status of the completed operation for telemetry.
    // A failed handle creation from a previously-blocked process is
    // an indicator that our pre-op access stripping is effective.
    //
    if (!NT_SUCCESS(OperationInformation->ReturnStatus)) {
        InterlockedIncrement64(&state->Stats.BlockedTransactions);
    }
}

// ============================================================================
// INTERNAL CLEANUP
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowEvictLruTransaction(
    VOID
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    PLIST_ENTRY entry;
    PSHADOW_KTM_TRANSACTION transaction;

    //
    // Caller holds Lock exclusively.
    //

    if (!IsListEmpty(&state->TransactionList)) {
        entry = RemoveTailList(&state->TransactionList);
        transaction = CONTAINING_RECORD(entry, SHADOW_KTM_TRANSACTION, ListEntry);

        InterlockedExchange(&transaction->RemovedFromList, TRUE);
        InterlockedDecrement(&state->TransactionCount);

        ShadowReleaseKtmTransaction(transaction);
    }
}

/**
 * @brief Cleanup all transaction tracking entries with reference draining.
 *
 * Called after ObUnRegisterCallbacks returns, so no new callbacks can fire.
 * Marks each entry as removed from list, then drains references.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupTransactionEntries(
    VOID
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    PLIST_ENTRY entry;
    PSHADOW_KTM_TRANSACTION transaction;
    LARGE_INTEGER drainInterval;
    ULONG totalLeaked = 0;

    PAGED_CODE();

    if (!state->LockInitialized) {
        return;
    }

    drainInterval.QuadPart = -((LONGLONG)SHADOW_REFCOUNT_DRAIN_INTERVAL_MS * 10000LL);

    FsRtlAcquirePushLockExclusive(&state->Lock);

    while (!IsListEmpty(&state->TransactionList)) {
        entry = RemoveHeadList(&state->TransactionList);
        transaction = CONTAINING_RECORD(entry, SHADOW_KTM_TRANSACTION, ListEntry);

        InterlockedExchange(&transaction->RemovedFromList, TRUE);
        InterlockedDecrement(&state->TransactionCount);

        //
        // Drain outstanding references with timeout.
        // Since callbacks are already unregistered, no NEW references
        // can be taken — we only wait for in-flight ones to complete.
        //
        ULONG spinCount = 0;
        while (transaction->ReferenceCount > 1 &&
               spinCount < SHADOW_REFCOUNT_DRAIN_MAX_ITERATIONS) {

            FsRtlReleasePushLockExclusive(&state->Lock);
            KeDelayExecutionThread(KernelMode, FALSE, &drainInterval);
            FsRtlAcquirePushLockExclusive(&state->Lock);

            spinCount++;
        }

        if (transaction->ReferenceCount == 1) {
            ShadowReleaseKtmTransaction(transaction);
        } else {
            totalLeaked++;
            InterlockedIncrement64(&state->Stats.TransactionsLeaked);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Transaction leaked (refcount=%ld)\n",
                       transaction->ReferenceCount);
        }
    }

    FsRtlReleasePushLockExclusive(&state->Lock);

    if (totalLeaked > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] %lu transactions leaked during cleanup\n",
                   totalLeaked);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowCleanupKtmAlertQueue(
    VOID
    )
{
    PSHADOW_KTM_MONITOR_STATE state = &g_KtmMonitorState;
    PLIST_ENTRY entry;
    PSHADOW_KTM_ALERT alert;
    KIRQL oldIrql;

    PAGED_CODE();

    KeAcquireSpinLock(&state->AlertLock, &oldIrql);

    while (!IsListEmpty(&state->AlertQueue)) {
        entry = RemoveHeadList(&state->AlertQueue);
        alert = CONTAINING_RECORD(entry, SHADOW_KTM_ALERT, ListEntry);
        state->AlertCount--;

        if (state->AlertLookasideInitialized) {
            ExFreeToNPagedLookasideList(&state->AlertLookaside, alert);
        } else {
            ExFreePoolWithTag(alert, SHADOW_KTM_ALERT_TAG);
        }
    }

    KeReleaseSpinLock(&state->AlertLock, oldIrql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Cleaned up KTM alert queue\n");
}
